use std::io::Write;

use crate::cli::{parse_flags, print_claim_help, resolve_globals, CliError, Deps};
use crate::color::{color_func, DIM, LABEL, WARN};
use crate::envelope::{self, EnvelopeError, OpenParams};
use crate::passphrase::{resolve_passphrase, write_error};

pub fn run_claim(args: &[String], deps: &mut Deps) -> i32 {
    let mut pa = match parse_flags(args) {
        Ok(pa) => pa,
        Err(CliError::ShowHelp) => {
            print_claim_help(deps);
            return 0;
        }
        Err(CliError::Error(e)) => {
            write_error(&mut deps.stderr, false, (deps.is_tty)(), &e);
            return 2;
        }
    };
    resolve_globals(&mut pa, deps);

    if pa.args.is_empty() {
        write_error(
            &mut deps.stderr,
            pa.json,
            (deps.is_tty)(),
            "share URL is required",
        );
        return 2;
    }

    let share_url = &pa.args[0];

    // Parse URL to extract ID and url_key
    let (id, url_key) = match envelope::parse_share_url(share_url) {
        Ok(r) => r,
        Err(e) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                (deps.is_tty)(),
                &format!("invalid share URL: {}", e),
            );
            return 2;
        }
    };

    // Derive base URL from share URL if not explicitly set via flag/env
    let base_url = if !pa.base_url_from_flag && (deps.getenv)("SECRET_BASE_URL").is_none() {
        // Try to extract base URL from share URL
        if share_url.contains("://") {
            if let Some(scheme_end) = share_url.find("://") {
                let after_scheme = &share_url[scheme_end + 3..];
                if let Some(path_start) = after_scheme.find('/') {
                    share_url[..scheme_end + 3 + path_start].to_string()
                } else {
                    pa.base_url.clone()
                }
            } else {
                pa.base_url.clone()
            }
        } else {
            pa.base_url.clone()
        }
    } else {
        pa.base_url.clone()
    };

    // Derive claim token from url_key alone
    let claim_token = match envelope::derive_claim_token(&url_key) {
        Ok(t) => t,
        Err(e) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                (deps.is_tty)(),
                &format!("key derivation failed: {}", e),
            );
            return 1;
        }
    };

    // Claim from server
    let client = (deps.make_api)(&base_url, &pa.api_key);

    let resp = match client.claim(&id, &claim_token) {
        Ok(r) => r,
        Err(e) => {
            write_error(
                &mut deps.stderr,
                pa.json,
                (deps.is_tty)(),
                &format!("claim failed: {}", e),
            );
            return 1;
        }
    };

    let is_tty = (deps.is_tty)();
    let needs_pass = envelope::requires_passphrase(&resp.envelope);

    // Determine if an explicit passphrase flag was set
    let explicit_flag =
        pa.passphrase_prompt || !pa.passphrase_env.is_empty() || !pa.passphrase_file.is_empty();

    // --- Phase A: Explicit flag set → use only that passphrase ---
    if explicit_flag {
        let mut passphrase = match resolve_passphrase(&pa, deps) {
            Ok(p) => p,
            Err(e) => {
                write_error(&mut deps.stderr, pa.json, is_tty, &e);
                return 1;
            }
        };

        let can_retry = pa.passphrase_prompt && is_tty && needs_pass;
        let plaintext = loop {
            match envelope::open(OpenParams {
                envelope: resp.envelope.clone(),
                url_key: url_key.clone(),
                passphrase: passphrase.clone(),
            }) {
                Ok(p) => break p,
                Err(EnvelopeError::DecryptionFailed) if can_retry => {
                    let c = color_func(is_tty);
                    let _ = writeln!(deps.stderr, "{}", c(WARN, "Wrong passphrase, try again."));
                    let prompt_c = color_func(true);
                    let prompt = format!("{} ", prompt_c(LABEL, "Passphrase:"));
                    match (deps.read_pass)(&prompt, &mut deps.stderr) {
                        Ok(p) if !p.is_empty() => passphrase = p,
                        Ok(_) => {
                            write_error(
                                &mut deps.stderr,
                                pa.json,
                                is_tty,
                                "passphrase must not be empty",
                            );
                            return 1;
                        }
                        Err(e) => {
                            write_error(
                                &mut deps.stderr,
                                pa.json,
                                is_tty,
                                &format!("read passphrase: {}", e),
                            );
                            return 1;
                        }
                    }
                }
                Err(e) => {
                    write_error(&mut deps.stderr, pa.json, is_tty, &e.to_string());
                    return 1;
                }
            }
        };

        return output_plaintext(&plaintext, &pa, deps, &resp.expires_at);
    }

    // --- Phase B: Try configured passphrases (default + decryption list) ---
    {
        // Build candidate list: default passphrase first, then decryption_passphrases, deduped
        let mut candidates: Vec<String> = Vec::new();
        if !pa.passphrase_default.is_empty() {
            candidates.push(pa.passphrase_default.clone());
        }
        for p in &pa.decryption_passphrases {
            if !p.is_empty() && !candidates.contains(p) {
                candidates.push(p.clone());
            }
        }

        // If envelope doesn't need a passphrase, try empty passphrase (no-passphrase path)
        if !needs_pass {
            match envelope::open(OpenParams {
                envelope: resp.envelope.clone(),
                url_key: url_key.clone(),
                passphrase: String::new(),
            }) {
                Ok(plaintext) => return output_plaintext(&plaintext, &pa, deps, &resp.expires_at),
                Err(EnvelopeError::DecryptionFailed) => {
                    // Fall through to candidates or prompt
                }
                Err(e) => {
                    write_error(&mut deps.stderr, pa.json, is_tty, &e.to_string());
                    return 1;
                }
            }
        }

        // Try each candidate
        for candidate in &candidates {
            match envelope::open(OpenParams {
                envelope: resp.envelope.clone(),
                url_key: url_key.clone(),
                passphrase: candidate.clone(),
            }) {
                Ok(plaintext) => return output_plaintext(&plaintext, &pa, deps, &resp.expires_at),
                Err(EnvelopeError::DecryptionFailed) => continue,
                Err(e) => {
                    write_error(&mut deps.stderr, pa.json, is_tty, &e.to_string());
                    return 1;
                }
            }
        }

        // All candidates failed (or no candidates existed)
        let tried = candidates.len();

        // --- Phase C: Fallback to interactive prompt or error ---
        if !needs_pass && tried == 0 {
            // No passphrase needed and decryption failed with empty passphrase — this is
            // a genuine decryption error (wrong URL key), not a passphrase issue
            write_error(&mut deps.stderr, pa.json, is_tty, "decryption failed");
            return 1;
        }

        if !is_tty {
            if tried > 0 {
                write_error(
                    &mut deps.stderr,
                    pa.json,
                    false,
                    &format!(
                        "this secret is passphrase-protected; tried {} configured passphrase(s) \
                         but none matched. Use -p, --passphrase-env, or --passphrase-file",
                        tried,
                    ),
                );
            } else {
                write_error(
                    &mut deps.stderr,
                    pa.json,
                    false,
                    "this secret is passphrase-protected; use -p, --passphrase-env, or --passphrase-file",
                );
            }
            return 1;
        }

        // TTY: show notice and prompt interactively
        if !pa.silent {
            let c = color_func(true);
            if tried > 0 {
                let _ = writeln!(
                    deps.stderr,
                    "{} {}",
                    c(WARN, "\u{26b7}"),
                    c(
                        DIM,
                        &format!(
                        "Passphrase-protected \u{2014} {} configured passphrase(s) didn't match",
                        tried,
                    )
                    )
                );
            } else {
                let _ = writeln!(
                    deps.stderr,
                    "{} {}",
                    c(WARN, "\u{26b7}"),
                    c(DIM, "This secret is passphrase-protected")
                );
            }
        }

        // Interactive retry loop
        loop {
            let c = color_func(true);
            let prompt = format!("{} ", c(LABEL, "Passphrase:"));
            let passphrase = match (deps.read_pass)(&prompt, &mut deps.stderr) {
                Ok(p) if !p.is_empty() => p,
                Ok(_) => {
                    write_error(
                        &mut deps.stderr,
                        pa.json,
                        is_tty,
                        "passphrase must not be empty",
                    );
                    return 1;
                }
                Err(e) => {
                    write_error(
                        &mut deps.stderr,
                        pa.json,
                        is_tty,
                        &format!("read passphrase: {}", e),
                    );
                    return 1;
                }
            };

            match envelope::open(OpenParams {
                envelope: resp.envelope.clone(),
                url_key: url_key.clone(),
                passphrase,
            }) {
                Ok(plaintext) => return output_plaintext(&plaintext, &pa, deps, &resp.expires_at),
                Err(EnvelopeError::DecryptionFailed) => {
                    let c = color_func(is_tty);
                    let _ = writeln!(deps.stderr, "{}", c(WARN, "Wrong passphrase, try again."));
                    continue;
                }
                Err(e) => {
                    write_error(&mut deps.stderr, pa.json, is_tty, &e.to_string());
                    return 1;
                }
            }
        }
    }
}

/// Output decrypted plaintext to stdout in the appropriate format.
fn output_plaintext(
    plaintext: &[u8],
    pa: &crate::cli::ParsedArgs,
    deps: &mut Deps,
    expires_at: &str,
) -> i32 {
    if pa.json {
        let out = serde_json::json!({
            "plaintext": String::from_utf8_lossy(plaintext),
            "expires_at": expires_at,
        });
        let _ = writeln!(deps.stdout, "{}", serde_json::to_string(&out).unwrap());
    } else {
        if (deps.is_stdout_tty)() && !pa.silent {
            let c = color_func(true);
            let _ = writeln!(deps.stderr, "{}", c(LABEL, "Secret:"));
        }
        let _ = deps.stdout.write_all(plaintext);
        // Add a trailing newline for clean terminal display, but only when
        // stdout is a TTY and the secret doesn't already end with one.
        // Piped output remains byte-exact to preserve secret integrity.
        if (deps.is_stdout_tty)() && !plaintext.ends_with(b"\n") {
            let _ = writeln!(deps.stdout);
        }
    }
    0
}
