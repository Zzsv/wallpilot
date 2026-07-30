## What changed

<!-- Describe the focused change and why it is needed. -->

## User and security impact

<!-- Include lockout risk, privilege changes, sensitive data handling, and rollback. -->

## Validation

<!-- List automated and manual checks. -->

## Checklist

- [ ] The change does not convert user input into shell commands.
- [ ] Root operations remain inside the typed Unix-socket agent.
- [ ] Risky or destructive behavior has preview, confirmation, audit, and rollback.
- [ ] Tests cover the new behavior and important failures.
- [ ] User-facing documentation and `CHANGELOG.md` are updated where needed.
- [ ] No secrets, real server addresses, access paths, or recovery codes are included.
