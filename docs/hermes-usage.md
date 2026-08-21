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

For a `local_proxy` grant, issuing the capability is safe because the returned
`khcap_…` value is short-lived, route-bound, method-bound, revocable, and cannot
be used directly against the upstream service:

```bash
keyholder issue openrouter-chat-proxy --ttl 300 --reason "call OpenRouter through local proxy"
```

Use the returned capability as the bearer token and
`http://127.0.0.1:8787` as the API base. The local listener validates the
capability and substitutes the real upstream bearer credential only while
forwarding an allowed request. The example policy uses the Bitwarden reference
`key:openrouter` and permits `/v1/chat/completions`; with
`upstream_base_url: https://openrouter.ai/api`, do not include `/api` in the
allowed route. Never configure `allow_insecure_http: true` for
an Internet upstream; that option exists only for controlled local testing.
The opt-in must be the YAML boolean `true`; quoted values such as `"true"` or
`"false"` are rejected rather than interpreted by truthiness.
The listener is off for backward compatibility unless the operator sets
`proxy.enabled: true` in the daemon policy.
Capabilities are daemon-memory state and fail closed on restart; issue a new
capability if the daemon restarts even if its old lease row remains in SQLite.
