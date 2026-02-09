# Changelog

## 0.1.0 — 2026-02-09

Initial release.

- **Commands:** `create`, `claim`, `burn`, `config`, `completion`
- **Crypto:** AES-256-GCM + HKDF-SHA256, optional PBKDF2 passphrases, zero-knowledge client-side encryption via `ring`
- **Config:** TOML config file (`~/.config/secrt/config.toml`) with `config init`, env vars, CLI flag precedence
- **Keychain:** Optional OS keychain integration (macOS Keychain, Linux keyutils, Windows Credential Manager) for passphrase storage
- **Claim:** Auto-tries configured `decryption_passphrases`, falls back to interactive prompt on TTY
- **Input:** Stdin pipe, `--text`, `--file`, `--multi-line`, `--trim`, hidden/shown interactive input
- **Output:** Human-friendly TTY output with color, `--json` for scripting, `--silent` mode
- **Shell completions:** Bash, Zsh, Fish via `completion` command
- **No async runtime** — blocking HTTP via `ureq`, ~1.5 MB static binary
