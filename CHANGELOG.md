# Changelog

All notable changes to WallPilot are documented in this file. The project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-07-31

### Added

- Cross-distribution detection for major Debian, RHEL, SUSE, and Arch families.
- Active-backend detection with read-only conflict mode.
- Writable firewalld and UFW adapters with fixed argument validation.
- Read-only nftables and legacy iptables inspection.
- Firewall lifecycle controls restricted to detected firewall service units.
- A 90-second trial, confirmation, and automatic rollback workflow.
- Recoverable deletion with integrity-checked snapshots and batch restore.
- Permanent purge protected by password, TOTP, and explicit confirmation.
- Server, network, listener, connection, container, and security status panels.
- A privileged Unix-socket agent separated from the unprivileged web process.
- Random management paths, Argon2id, CSRF protection, secure sessions, CSP,
  Host/Origin validation, and login rate limiting.
- `wallpilot doctor` for read-only installation and exposure diagnostics.
- Version-pinned one-command HTTPS bootstrap installer with mandatory SHA-256
  verification.
- Python 3.10, 3.12, and 3.14 GitHub Actions test matrix.

### Security

- No arbitrary shell, systemctl, nft, or iptables input is accepted.
- The web service listens only on `127.0.0.1` by default.
- Unconfirmed risky changes are rolled back automatically.

[Unreleased]: https://github.com/Zzsv/wallpilot/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Zzsv/wallpilot/releases/tag/v0.1.0
