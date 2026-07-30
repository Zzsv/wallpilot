# Contributing to WallPilot

感谢你帮助改进 WallPilot。安全边界是这个项目的一部分，而不是发布后的补充工作。

Thank you for helping improve WallPilot. Its safety boundaries are part of the
product, not cleanup work to be added after a feature ships.

## Before opening an issue

- Use GitHub Discussions for usage questions and deployment ideas.
- Use the bug form for reproducible defects.
- Follow `SECURITY.md` for vulnerabilities. Do not publish secrets, server
  addresses, access paths, recovery codes, or exploit details in an Issue.
- Search existing Issues before opening a duplicate.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
pytest
```

Tests must use `FakeRunner` or an injected firewall adapter. Development tests
must never change the workstation firewall.

## Pull request scope

Keep each pull request focused on one behavior. Explain:

- what changed and why;
- user and operator impact;
- security or lockout implications;
- how the change was verified;
- which Issue it resolves, when applicable.

## Non-negotiable safety rules

- Never turn user input into a shell command.
- Use argument arrays with `shell=False`.
- Do not accept arbitrary systemd unit names.
- Keep root operations in the typed Unix-socket agent.
- Preserve automatic rollback for risky changes.
- Never expose the management path, passwords, TOTP secrets, agent keys, or
  recovery codes in logs, diagnostics, fixtures, or screenshots.
- New destructive actions require preview, explicit confirmation, audit, and a
  documented recovery path.
- Cloud security groups and non-firewall services remain out of scope.

## Tests and documentation

- Add focused tests for new behavior and failure cases.
- Include Python 3.10 compatibility.
- Update both `README.md` and `README.en.md` when user-facing instructions
  change.
- Update `CHANGELOG.md` for release-relevant changes.
- Run `git diff --check` before publishing.

By submitting a contribution, you agree that it may be distributed under the
project's MIT license.
