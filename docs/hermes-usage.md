# Hermes usage

Prefer `keyholder run` so Hermes sees only command output, not credentials:

```bash
keyholder run github-readonly --env GITHUB_TOKEN --ttl 300 --reason "Inspect repository metadata" -- gh repo view OWNER/REPO --json name
```

Avoid unless necessary because the temporary token enters the transcript:

```bash
keyholder issue github-readonly --ttl 300 --reason "Need temporary GitHub token" --format json
```

Rules:

- Do not ask Bitwarden directly for secrets.
- Do not read `/etc/keyholder` files.
- Do not print tokens unless the user explicitly requests it.
- Use the narrowest grant and shortest TTL.
- Prefer a provider that mints short-lived credentials. The `local_proxy` provider is planned and is not yet a deployable boundary for static upstream keys.

For Google Workspace CLI, use a purpose-named grant such as `google-calendar-read`:

```bash
keyholder run google-calendar-read --env GOOGLE_WORKSPACE_CLI_TOKEN --ttl 300 --reason "read calendar" -- \
  gws calendar events list --calendarId primary
```

Do not use `keyholder issue` for this in Hermes. Google OAuth scopes are fixed when the refresh token is consented; a grant label does not narrow a broader OAuth grant. Google's `expires_in` controls direct token validity, while Keyholder's TTL controls the broker lease only.

The `local_proxy` provider is planned work. It currently issues opaque `khcap_…` capability tokens, but no forwarding listener consumes them yet. Do not use `local_proxy` as a deployable security boundary or configure it as though it can proxy requests; the listener and associated capability validation, forwarding, and policy behavior are not available yet.
