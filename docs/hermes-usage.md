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
The capability listener is off for backward compatibility unless the operator sets
`proxy.enabled: true`. The long-running gateway endpoint is a separate, opt-in
HTTP-over-Unix-socket listener: set `proxy.unix_socket_path` to an absolute path
to enable it. Use `unix_socket_group: keyholder-clients` and
`unix_socket_mode: "0o660"` (the only safe modes are owner read/write with
optional group read/write). The parent directory must not be writable by group
or other users. `SO_PEERCRED` identifies the process; do not add a bearer token.
The TCP flow above uses the legacy `openrouter-chat-proxy` capability grant and
`keyholder issue`/`keyholder run`; the UDS flow uses the separate
`openrouter-chat-peer-proxy` grant and has no token or `keyholder run` step.

The peer endpoint requires exactly one matching `local_proxy` grant with
`authentication: peercred`; `openrouter-chat-peer-proxy` is the example name.
The grant must set `allowed_methods: [POST]`,
`allowed_routes: [/v1/chat/completions]`, and exactly
`allowed_models: [stealth/ox-alpha]`. Its `bitwarden_refs` may contain only a
reference such as `upstream_api_key: "key:openrouter"`; never put the upstream
key in Hermes environment, configuration, prompts, logs, or sessions. Hermes
does not issue a capability and must not use `keyholder run` for this endpoint.

Current limitation: Hermes needs a UDS-capable OpenAI client adapter before its
gateway can consume this endpoint. Until that adapter exists, use a local
UDS-capable test client only; do not substitute the TCP capability proxy.

After changing policy or socket settings, validate the YAML and restart the
daemon (`sudo systemctl restart keyholder.service`). Confirm readiness without
printing a token or making an upstream request:

```bash
keyholder doctor
sudo systemctl is-active keyholder.service
sudo stat -c '%A %U:%G %n' /run/keyholder/openrouter.sock
```

The daemon removes the socket on clean shutdown and recreates it on startup;
it refuses unsafe parents, traversal, stale non-socket files, malformed modes,
or ambiguous/missing peer grants. Requests are audited as attempts and
completion/rejection/failure events with secret-like fields redacted; monitor
these JSON logs and request/error/latency metrics in journald/Loki. A daemon
restart invalidates in-memory request state. To revoke access, remove the
grant or socket path and restart; to roll back, unset `unix_socket_path` and
restart. Existing TCP capability-proxy behavior is unchanged.
Capabilities are daemon-memory state and fail closed on restart; issue a new
capability if the daemon restarts even if its old lease row remains in SQLite.
