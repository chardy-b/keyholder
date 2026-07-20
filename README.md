# keyholder

A local, Unix-socket-only token broker that keeps long-lived credentials out of the reach of the processes that need to use them.

You have long-lived secrets (a GitHub App private key, AWS access keys, third-party API keys). You have processes — automation scripts, AI agents, or dev tooling — that need *some* credential to do their job, but shouldn't hold the crown jewels. keyholder sits between them: it holds the long-lived material, authenticates callers by Linux peer credentials, checks a YAML policy, and hands out short-lived, narrowly scoped credentials on demand.

Every issue is logged, every credential expires quickly, and any credential can be revoked instantly without rotating the upstream secret.

## Status

Deployable and tested end-to-end today for GitHub App tokens (read and write). AWS STS is implemented and ready for a smoke test against a real role. The `local_proxy` provider — for wrapping static third-party API keys behind capability tokens — is stubbed but not yet consumable; the forwarding HTTP listener is the next major piece of work (see [Roadmap](#roadmap)).

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

## Providers

| Provider      | What it mints                                           | Status                        |
| ------------- | ------------------------------------------------------- | ----------------------------- |
| `github_app`  | GitHub App installation access tokens (via JWT)         | Tested end-to-end             |
| `aws_sts`     | AWS session credentials (`AKIA…` + session token)       | Implemented, awaiting smoke test |
| `local_proxy` | Opaque capability tokens (`khcap_…`) for a future proxy | Issues tokens; consumer pending |
| `fake`        | Deterministic fake credential for tests                 | Test-only                     |

Adding a new provider means writing a class with a single `issue(grant, secrets, ttl) -> IssuedCredential` method — see [`src/keyholderd/providers/base.py`](src/keyholderd/providers/base.py).

## Requirements

- Linux with `systemd` ≥ 254 (uses `LoadCredentialEncrypted=`, `ProtectSystem`, `NoNewPrivileges`, `RuntimeDirectory`)
- Python ≥ 3.11
- The [Bitwarden Secrets Manager CLI (`bws`)](https://bitwarden.com/help/secrets-manager-cli/) on `PATH`
- A Bitwarden Secrets Manager machine account with access to your secrets

## Installation

The install below assumes a single-host deployment. It creates a dedicated `keyholder` system user, installs the daemon into `/opt/keyholder`, and wires up the systemd service.

### 1. Encrypt the Bitwarden access token

Create a machine account token in the Bitwarden Secrets Manager UI (see [Bitwarden docs](https://bitwarden.com/help/access-tokens/)). Then encrypt it as a systemd credential — the plaintext never touches disk:

```bash
sudo install -d -o root -g keyholder -m 0750 /etc/keyholder
sudo systemd-creds encrypt --name=bws-access-token - /etc/keyholder/bws-access-token.cred
# paste the token, hit Enter, then Ctrl-D
sudo chown root:keyholder /etc/keyholder/bws-access-token.cred
sudo chmod 0640 /etc/keyholder/bws-access-token.cred
```

Verify with:

```bash
sudo systemd-creds decrypt --name=bws-access-token /etc/keyholder/bws-access-token.cred - | head -c 20; echo
```

### 2. Create users, groups, and directories

```bash
sudo groupadd --system keyholder
sudo useradd  --system --home /var/lib/keyholder --shell /usr/sbin/nologin --gid keyholder keyholder
sudo groupadd --system keyholder-clients
sudo usermod  -aG keyholder-clients keyholder          # daemon needs this to chgrp the socket
sudo usermod  -aG keyholder-clients "$USER"            # you (or whoever will call it) need this to reach the socket

sudo install -d -o root      -g keyholder -m 0750 /etc/keyholder
sudo install -d -o keyholder -g keyholder -m 0700 /var/lib/keyholder
sudo install -d -o keyholder -g adm       -m 0750 /var/log/keyholder
```

Group changes only take effect in **new** shells. Run `newgrp keyholder-clients` for a group-active subshell or log out and back in.

### 3. Install the daemon

Build a venv outside `/home` so `ProtectHome=true` in the service unit doesn't hide it:

```bash
sudo python3 -m venv /opt/keyholder/venv
sudo /opt/keyholder/venv/bin/pip install --upgrade pip
sudo /opt/keyholder/venv/bin/pip install /path/to/this/repo
sudo install -m 0755 /opt/keyholder/venv/bin/keyholder  /usr/local/bin/keyholder
sudo install -m 0755 /opt/keyholder/venv/bin/keyholderd /usr/local/bin/keyholderd
```

### 4. Install the policy and service unit

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

### 5. Confirm the caller can reach it

In a `keyholder-clients`-active shell:

```bash
keyholder grants
```

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
              private_key_pem: "<bws-secret-uuid>"
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
              aws_access_key_id:     "<bws-secret-uuid>"
              aws_secret_access_key: "<bws-secret-uuid>"
```

See [`packaging/policy.example.yaml`](packaging/policy.example.yaml) for a fuller starter policy.

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
```

**Every request requires a `--reason`.** Reasons are recorded in the audit log so you can trace why any given credential was minted.

## Security model

- **Long-lived material never touches the caller.** The Bitwarden access token is delivered to the daemon only via `LoadCredentialEncrypted=` — it lives in a tmpfs inside the daemon's private mount namespace. Provider secrets fetched from Bitwarden stay in the daemon's process memory and are never returned to callers.
- **Authorization is Unix-native.** No shared secrets, API keys, or JWTs between caller and daemon. Just `SO_PEERCRED` plus filesystem permissions on the socket.
- **Least privilege at every layer.** Grants are per-caller, per-profile, with a hard `max_ttl_seconds` cap and per-provider scope constraints (GitHub App permissions, AWS role ARNs, allowed proxy routes).
- **Short-lived by default.** Tokens are minted with an expiry; leases are recorded so any credential can be revoked immediately without rotating the upstream key.
- **Audit-first.** Every `grants`, `issue`, `run`, and `revoke` request writes a JSONL record to `/var/log/keyholder/audit.jsonl`. Fields matching secret-like names (`access_token`, `private_key`, `upstream_api_key`, `*_secret`, `*_token`) are rejected at write time, so a code bug can't leak a value into the log.
- **Systemd hardening.** `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `LockPersonality`.

## Development

```bash
uv venv
uv pip install -e '.[test]'
uv run pytest -v
```

The full test suite (54 tests) covers policy parsing, lease persistence, audit-log sanitization, peer-credential resolution, each provider's issue logic, the Bitwarden resolver, the HTTP handler, the CLI (including `keyholder doctor`'s individual checks), and a fake-provider end-to-end round trip.

## Roadmap

The daemon and CLI are complete. Two meaningful gaps remain before keyholder covers every credential shape an automation might need:

1. **Local proxy consumer** — `LocalProxyProvider` mints opaque `khcap_…` capability tokens today, but nothing accepts them yet. The next major piece is a second HTTP listener inside the daemon that receives requests bearing a capability token, validates it against the lease store, checks the request path against the grant's allowlist, and forwards to the configured upstream with the *real* API key attached. That unlocks scoped, revocable, audit-logged access to third-party APIs whose long-lived keys never rotate (OpenRouter, OpenAI, Stripe, etc.).
2. **Run-as-caller** — today `keyholder run` executes the child subprocess as the daemon's own user (`keyholder`), which means CLIs that need caller-owned config (`gh`, `git` with your SSH keys, `aws` with your `~/.aws`) can't find it. Works fine for env-only tools like `curl`. Fixing this cleanly needs either a small setuid helper or a redesign that hands the token back with an exec envelope.

Other niceties: `GET /v1/leases` + `keyholder leases` for visibility, `SIGHUP` policy reload, a background sweep for expired lease rows, and a socket-activated systemd unit.

## Documentation

- [`docs/hermes-usage.md`](docs/hermes-usage.md) — rules for AI agent callers (narrowest grant, shortest TTL, prefer `run` over `issue`, never touch Bitwarden or upstream keys directly).
- [`docs/grafana-logging.md`](docs/grafana-logging.md) — scraping the daemon's structured logs and audit trail into Grafana Loki via Alloy/Promtail.

## License

TBD.
