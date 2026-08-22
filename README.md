# keyholder

A local, Unix-socket-only token broker that keeps long-lived credentials out of the reach of the processes that need to use them.

You have long-lived secrets (a GitHub App private key, AWS access keys, third-party API keys). You have processes — automation scripts, AI agents, or dev tooling — that need *some* credential to do their job, but shouldn't hold the crown jewels. keyholder sits between them: it holds the long-lived material, authenticates callers by Linux peer credentials, checks a YAML policy, and hands out short-lived, narrowly scoped credentials on demand.

Every issue is logged, every credential expires quickly, and any credential can be revoked instantly without rotating the upstream secret.

## Status

Deployable and tested end-to-end today for GitHub App tokens (read and write). AWS STS is implemented and ready for a smoke test against a real role. The `local_proxy` provider now exposes a loopback-only HTTP listener that validates short-lived capabilities, enforces method and route allowlists, and injects static third-party API keys only on the upstream request. Buffered HTTP request/response forwarding is implemented; transparent streaming remains a roadmap item.

## How it works

```
     ┌──────────────┐   Unix socket +      ┌───────────────┐   HTTPS   ┌───────────────┐
     │   caller     │   peer credentials   │  keyholderd   │──────────▶│   upstream    │
     │  (Hermes,    │ ────────────────────▶│               │           │ (GitHub, AWS, │
     │   scripts,   │                      │  policy.yaml  │  short-   │  Bitwarden,   │
     │   humans)    │◀────────────────────│               │  lived    │   etc.)       │
     └──────────────┘  short-lived token   └───────────────┘  secret   └───────────────┘
                                                  ▲
                                                  │ bws (subprocess)
                                                  ▼
                                          ┌───────────────┐
                                          │  Bitwarden    │
                                          │   Secrets     │
                                          │   Manager     │
                                          └───────────────┘
```

1. A caller connects to `/run/keyholder/keyholder.sock`.
2. The daemon reads the caller's Linux uid via `SO_PEERCRED` and resolves it to a username.
3. The username is looked up in `policy.yaml` to determine which **grants** the caller may request.
4. When the caller asks to `issue` (or `run`) a grant, the daemon resolves any long-lived material via the Bitwarden Secrets Manager CLI (`bws`), asks the appropriate **provider** to mint a short-lived credential, records a **lease** in SQLite, appends an **audit event**, and returns the credential.
5. Callers who prefer never to see the token can use `keyholder run <grant> --env VAR -- <cmd>` — the daemon spawns the child with `VAR` set in its environment, so the token exists only in that subprocess's memory.
6. For `local_proxy` grants, the caller receives only a `khcap_…` capability. Requests sent to the loopback proxy with that capability are method- and route-checked, then forwarded with the real upstream bearer credential substituted inside the daemon.

## Providers

| Provider      | What it mints                                           | Status                        |
| ------------- | ------------------------------------------------------- | ----------------------------- |
| `github_app`  | GitHub App installation access tokens (via JWT)         | Tested end-to-end             |
| `aws_sts`     | AWS session credentials (`AKIA…` + session token)       | Implemented, awaiting smoke test |
| `local_proxy` | Opaque capabilities or peercred UDS forwarding         | Buffered forwarding operational |
| `fake`        | Deterministic fake credential for tests                 | Test-only                     |

Adding a new provider means writing a class with a single `issue(grant, secrets, ttl) -> IssuedCredential` method — see [`src/keyholderd/providers/base.py`](src/keyholderd/providers/base.py).

## Requirements

- Linux with `systemd` ≥ 254 (uses `LoadCredentialEncrypted=`, `ProtectSystem`, `NoNewPrivileges`, `RuntimeDirectory`)
- Python ≥ 3.11
- The [Bitwarden Secrets Manager CLI (`bws`)](https://bitwarden.com/help/secrets-manager-cli/) on `PATH`
- A Bitwarden Secrets Manager machine account with access to your secrets

## Installation

Prerequisites: Linux with systemd ≥ 254, Python ≥ 3.11, and `bws` on `PATH` (see [Requirements](#requirements)).

```bash
git clone <this-repo-url> keyholder && cd keyholder
sudo packaging/install.sh --client-user "$USER"
keyholder doctor
```

`install.sh` creates the `keyholder` system user and `keyholder-clients` group, installs the daemon into `/opt/keyholder`, encrypts your Bitwarden access token as a systemd credential (prompts interactively unless `--bws-token-file PATH` is given), installs the example policy (only if none exists), and starts the service. It is idempotent — re-run it any time, including after `git pull` (see [Upgrading](#upgrading)).

`--client-user "$USER"` adds you to `keyholder-clients` so you can reach the socket; group membership only takes effect in **new** shells — run `newgrp keyholder-clients` or log back in, then `keyholder doctor` should report everything `ok`.

Before `keyholder grants` returns anything, edit `/etc/keyholder/policy.yaml` (the installer drops in `packaging/policy.example.yaml` as a starting point) and `sudo systemctl restart keyholder.service`.

Full usage: `sudo packaging/install.sh [--client-user USER] [--bws-token-file PATH] [--no-start]`.

<details>
<summary>Manual install (what the script does)</summary>

This is the mechanism `install.sh` automates — the reference for the `.deb` postinst, or for doing it by hand.

#### 1. Create users, groups, and directories

```bash
sudo groupadd --system keyholder
sudo useradd  --system --home /var/lib/keyholder --shell /usr/sbin/nologin --gid keyholder keyholder
sudo groupadd --system keyholder-clients
sudo usermod  -aG keyholder-clients keyholder          # daemon needs this to chgrp the socket
sudo usermod  -aG keyholder-clients "$USER"            # you (or whoever will call it) need this to reach the socket

sudo install -d -o root      -g keyholder -m 0750 /etc/keyholder
```

(`/var/lib/keyholder`, `/var/log/keyholder`, and `/run/keyholder` are created by `StateDirectory=`/`LogsDirectory=`/`RuntimeDirectory=` in the service unit — no manual `install -d` needed for those.)

Group changes only take effect in **new** shells. Run `newgrp keyholder-clients` for a group-active subshell or log out and back in.

#### 2. Encrypt the Bitwarden access token

Create a machine account token in the Bitwarden Secrets Manager UI (see [Bitwarden docs](https://bitwarden.com/help/access-tokens/)). Then encrypt it as a systemd credential — the plaintext never touches disk:

```bash
sudo systemd-creds encrypt --name=bws-access-token - /etc/keyholder/bws-access-token.cred
# paste the token, hit Enter, then Ctrl-D
sudo chown root:keyholder /etc/keyholder/bws-access-token.cred
sudo chmod 0640 /etc/keyholder/bws-access-token.cred
```

Verify with:

```bash
sudo systemd-creds decrypt --name=bws-access-token /etc/keyholder/bws-access-token.cred - | head -c 20; echo
```

**This file is sealed to the host's key/TPM and cannot be copied between machines** — every host encrypts its own copy (see [Replicating to another machine](#replicating-to-another-machine)).

#### 3. Install the daemon

Build a venv outside `/home` so `ProtectHome=true` in the service unit doesn't hide it:

```bash
sudo python3 -m venv /opt/keyholder/venv
sudo /opt/keyholder/venv/bin/pip install --upgrade pip
sudo /opt/keyholder/venv/bin/pip install /path/to/this/repo
sudo install -m 0755 /opt/keyholder/venv/bin/keyholder  /usr/local/bin/keyholder
sudo install -m 0755 /opt/keyholder/venv/bin/keyholderd /usr/local/bin/keyholderd
```

#### 4. Install the policy and service unit

```bash
sudo install -m 0640 -o root -g keyholder packaging/policy.example.yaml /etc/keyholder/policy.yaml
sudo install -m 0644 packaging/keyholder.service           /etc/systemd/system/keyholder.service
sudo systemctl daemon-reload
sudo systemctl enable --now keyholder.service
sudo systemctl status keyholder.service --no-pager
```

Verify the socket exists with the right perms:

```bash
sudo ls -la /run/keyholder/
# srw-rw---- 1 keyholder keyholder-clients … keyholder.sock
```

#### 5. Confirm the caller can reach it

In a `keyholder-clients`-active shell:

```bash
keyholder grants
```

</details>

### Upgrading

```bash
git pull
sudo packaging/install.sh
```

This reinstalls the package into the existing venv and restarts the service. It never touches an existing `policy.yaml` or `bws-access-token.cred`. Equivalent by hand: `sudo /opt/keyholder/venv/bin/pip install --force-reinstall --no-deps .` then `sudo systemctl restart keyholder.service`.

### Replicating to another machine

Two artifacts are host-specific and are never copied between machines:

- **`/etc/keyholder/policy.yaml`** — callers are identified by Linux username via `SO_PEERCRED`, so the policy is inherently per-host. Edit a fresh copy of `packaging/policy.example.yaml` for each new host.
- **`/etc/keyholder/bws-access-token.cred`** — sealed with `systemd-creds` to the host's own key/TPM; a copy from another machine will not decrypt. Run `packaging/install.sh` (or the manual encryption step) on each host to mint its own.

Everything else (the venv, the service unit, the sysusers fragment) is safe to reproduce by re-running `install.sh` on the new host.

### Installing a specific release

```bash
pip install git+<this-repo-url>@v0.2.0
```

works from any checkout or tag; there is no PyPI publication yet.

## Configuration

Grants are declared in `policy.yaml` under `callers.<name>.profiles.<profile>.grants`. Example:

```yaml
version: 1

bitwarden:
  backend: bws
  project_id: "00000000-0000-0000-0000-000000000000"
  cache_seconds: 300

paths:
  leases_db: /var/lib/keyholder/leases.db
  audit_log: /var/log/keyholder/audit.jsonl

proxy:
  enabled: true
  host: 127.0.0.1
  port: 8787
  max_body_bytes: 8388608
  max_response_bytes: 8388608
  max_workers: 16
  request_timeout_seconds: 15
  upstream_timeout_seconds: 30
  # Optional: enables the peer-credential OpenAI endpoint. No upstream key
  # belongs in Hermes; this reference is resolved only inside keyholderd.
  unix_socket_path: /run/keyholder/openrouter.sock
  unix_socket_group: keyholder-clients
  unix_socket_mode: "0o660"

callers:
  hermes:
    uid_name: hermes             # Linux username identified via SO_PEERCRED
    profiles:
      default:
        grants:
          - name: github-readonly
            provider: github_app
            ttl_seconds: 600
            max_ttl_seconds: 900
            app_id: 1234567
            installation_id: 12345678
            bitwarden_refs:
              private_key_pem: "key:github-app-private-key-pem"
            permissions:
              metadata: read
              contents: read

          - name: aws-s3-logs-read
            provider: aws_sts
            ttl_seconds: 900
            max_ttl_seconds: 1800
            role_arn: "arn:aws:iam::123456789012:role/logs-read"
            external_id: "keyholder-local"
            bitwarden_refs:
              aws_access_key_id:     "key:aws-source-access-key-id"
              aws_secret_access_key: "key:aws-source-secret-access-key"

          - name: openrouter-chat-proxy
            provider: local_proxy
            ttl_seconds: 300
            max_ttl_seconds: 600
            upstream_base_url: https://openrouter.ai/api
            bitwarden_refs:
              upstream_api_key: "key:openrouter"
            allowed_methods: [POST]
            allowed_routes: [/v1/chat/completions]
          - name: openrouter-chat-peer-proxy
            provider: local_proxy
            authentication: peercred
            ttl_seconds: 300
            max_ttl_seconds: 600
            upstream_base_url: https://openrouter.ai/api
            bitwarden_refs:
              upstream_api_key: "key:openrouter"
            allowed_methods: [POST]
            allowed_routes: [/v1/chat/completions]
            allowed_models: [stealth/ox-alpha]
```

Bitwarden references in policy examples must use either a canonical UUID string
or `key:<nonblank-name>`. A `key:` reference is matched exactly within the
configured Bitwarden project. These examples use placeholders only; never put
a real secret ID or secret value in tracked documentation.

See [`packaging/policy.example.yaml`](packaging/policy.example.yaml) for a fuller starter policy.

The optional `proxy.unix_socket_path` exposes an OpenAI-compatible endpoint
over a Unix socket authenticated with Linux `SO_PEERCRED`; it has no bearer
authentication. Set `unix_socket_group` to the dedicated client group and use
`unix_socket_mode: "0o660"` (or `"0o600"` when no group access is needed).
The daemon owns the socket and removes/recreates it during its lifecycle.
It fails closed on unsafe parents, non-socket stale paths, unsafe modes, or
missing/ambiguous peer grants. The separate `openrouter-chat-peer-proxy`
grant must explicitly use
`authentication: peercred`, POST `/v1/chat/completions`, and
`allowed_models: [stealth/ox-alpha]`; its Bitwarden reference is the only
location for the upstream key, which is never placed in Hermes.

This endpoint is opt-in and is enabled only when `unix_socket_path` is set.
Validate with `keyholder doctor`, `systemctl is-active`, and `stat` on the
socket—never by issuing a capability or sending a real upstream request.
Restart after policy changes. Audit events and daemon logs expose request,
latency, completion, rejection, and failure signals without credentials;
ship them to journald/Loki as described in
[`docs/grafana-logging.md`](docs/grafana-logging.md). Remove the grant or
unset `unix_socket_path`, then restart, to revoke/roll back access. Existing
in-memory state fails closed across restart.

**Hermes limitation:** the Hermes gateway needs a UDS-capable OpenAI client
adapter before it can consume this endpoint. Until then, use a UDS-capable
local client for validation; do not place an upstream key in Hermes.

The daemon loads policy at startup only. Restart the service (`sudo systemctl restart keyholder.service`) after editing.

## CLI

All commands respect `--socket <path>` (default `/run/keyholder/keyholder.sock`).

```bash
# List the grants your Unix user is allowed to request
keyholder grants

# Get a token as JSON (token appears in your shell — prefer `run`)
keyholder issue github-readonly --ttl 300 --reason "inspect repo metadata"

# Run a command with the token injected as an env var; token never touches your shell
keyholder run github-readonly --env GITHUB_TOKEN --ttl 300 --reason "list repos" -- \
    sh -c 'curl -sf -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/installation/repositories'

# Revoke an outstanding lease
keyholder revoke lease_abc123def --reason "no longer needed"

# local_proxy: mint a harmless short-lived capability, then use it as the
# bearer token against the loopback listener instead of the real upstream key
keyholder issue openrouter-chat-proxy --ttl 300 --reason "OpenRouter chat request"
# API base: http://127.0.0.1:8787

# The Unix-socket endpoint uses the separate peercred grant; it does not issue
# or accept a bearer capability token. Authentication is the caller's Linux
# process identity (SO_PEERCRED), not a Keyholder lease.

# Self-diagnose this host: systemd version, bws on PATH, service state, socket
# perms, group membership, policy/credential presence, and a live grants check
keyholder doctor
```

**Every request requires a `--reason`.** Reasons are recorded in the audit log so you can trace why any given credential was minted.

`keyholder doctor` prints one line per check (`ok` / `warn` / `fail` plus a hint on failure) and exits non-zero if anything failed. It does not require `sudo` — checks that need root (decrypting the `.cred` file) degrade to a `warn` instead of failing. It does not write audit events; the `grants` call it makes at the end is audited as usual.

## Security model

- **Long-lived material never touches the caller.** The Bitwarden access token is delivered to the daemon only via `LoadCredentialEncrypted=` — it lives in a tmpfs inside the daemon's private mount namespace. Provider secrets fetched from Bitwarden stay in the daemon's process memory and are never returned to callers.
- **Authorization is Unix-native.** No shared secrets, API keys, or JWTs between caller and daemon. Just `SO_PEERCRED` plus filesystem permissions on the socket.
- **Least privilege at every layer.** Grants are per-caller, per-profile, with a hard `max_ttl_seconds` cap and per-provider scope constraints (GitHub App permissions, AWS role ARNs, allowed proxy routes).
- **Short-lived by default.** Tokens are minted with an expiry; leases are recorded so any credential can be revoked immediately without rotating the upstream key.
- **Audit-first.** Every `grants`, `issue`, `run`, and `revoke` request writes a JSONL record to `/var/log/keyholder/audit.jsonl`. Fields matching secret-like names (`access_token`, `private_key`, `upstream_api_key`, `*_secret`, `*_token`) are rejected at write time, so a code bug can't leak a value into the log.
- **Secretless static-key forwarding.** When explicitly enabled, the proxy binds only to an explicit loopback IP, accepts opaque expiring capabilities, checks exact methods and routes, rejects ambiguous HTTP framing and duplicate headers, strips caller authorization and both static and `Connection`-nominated hop-by-hop headers, disables redirects, and writes an audit attempt before dispatch plus exactly one completion/failure event without recording either credential. HTTPS upstreams are required unless insecure HTTP is explicitly enabled with the literal boolean `true` for controlled local testing. Request/response sizes, concurrent workers, total downstream request duration, and total upstream duration are bounded. The credential-bearing upstream operation runs in a short-lived worker process so an absolute deadline can terminate a trickling connection.
- **Systemd hardening.** `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `LockPersonality`.

## Development

```bash
uv venv
uv pip install -e '.[test]'
uv run pytest -v
```

The full test suite covers policy parsing, lease persistence, audit-log sanitization, peer-credential resolution, each provider's issue logic, capability authorization and lifecycle, proxy forwarding and audit behavior, the Bitwarden resolver, the Unix-socket HTTP handler, the CLI (including `keyholder doctor`'s individual checks), and a fake-provider end-to-end round trip.

## Roadmap

The next meaningful gaps are:

1. **Streaming proxy responses** — the local proxy currently buffers request and response bodies. Add transparent streaming, including SSE, while preserving body limits, audit semantics, revocation checks, and header sanitization.
2. **Run-as-caller** — today `keyholder run` executes the child subprocess as the daemon's own user (`keyholder`), which means CLIs that need caller-owned config (`gh`, `git` with your SSH keys, `aws` with your `~/.aws`) can't find it. Works fine for env-only tools like `curl`. Fixing this cleanly needs either a small setuid helper or a redesign that hands the token back with an exec envelope.
3. **Richer proxy authentication adapters** — bearer injection is implemented. Header-key, query-key, request-signing, and protocol-specific adapters remain future work.

Other niceties: `GET /v1/leases` + `keyholder leases` for visibility, `SIGHUP` policy reload, cleanup of expired SQLite lease rows, and a socket-activated systemd unit.

Proxy capabilities are intentionally in-memory and fail closed across daemon
restarts. Existing SQLite lease rows may remain visible, but callers must issue
a new capability after restart. Buffered forwarding also incurs one short-lived
worker process per upstream request; streaming and a persistent bounded worker
pool are future optimizations.

## Documentation

- [`docs/hermes-usage.md`](docs/hermes-usage.md) — rules for AI agent callers (narrowest grant, shortest TTL, prefer `run` over `issue`, never touch Bitwarden or upstream keys directly).
- [`docs/grafana-logging.md`](docs/grafana-logging.md) — scraping the daemon's structured logs and audit trail into Grafana Loki via Alloy/Promtail.
- [`CHANGELOG.md`](CHANGELOG.md) — notable changes per release.

## License

TBD.
