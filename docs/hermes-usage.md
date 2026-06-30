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
- Prefer a provider that mints short-lived credentials. Static upstream keys must stay behind `local_proxy` capability tokens.
