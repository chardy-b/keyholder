# CLAUDE.md

Guidance for Claude Code when working in this repo.

## Before you do anything

Read these first, in order:

1. [`README.md`](README.md) — what this project is, current status, architecture, install, CLI, security model, and roadmap. Do not repeat these facts back to the user; assume they know.
2. [`docs/hermes-usage.md`](docs/hermes-usage.md) — the rules for using keyholder as a caller. **These apply to you.** In particular: prefer `keyholder run` over `issue` so tokens never enter your transcript; never touch Bitwarden or upstream API keys directly; use the narrowest grant and shortest TTL.
3. [`docs/grafana-logging.md`](docs/grafana-logging.md) — how the daemon's structured logs and audit trail are consumed downstream. Relevant when changing log format or adding audit events.

Skim any other files you add under `docs/` before starting work — they are the single source of truth for project-specific guidance.

## Codebase orientation

- `src/keyholderd/server.py` — the Unix-socket HTTP daemon. Routes: `GET /v1/grants`, `POST /v1/issue`, `POST /v1/run`, `POST /v1/revoke`.
- `src/keyholderd/cli.py` — the `keyholder` CLI client (`grants`, `issue`, `run`, `revoke`, `doctor`). Speaks the same HTTP over the Unix socket.
- `src/keyholderd/policy.py` — YAML policy loader, caller/grant lookup, TTL validation.
- `src/keyholderd/leases.py` — SQLite-backed lease store.
- `src/keyholderd/audit.py` — JSONL audit writer. **Hard-blocks any field name matching a secret-like pattern** (`access_token`, `private_key`, `*_secret`, `*_token`, …). If you add a new audit event, do not include secret values, hashes of raw secrets, or anything that would trip this check.
- `src/keyholderd/bitwarden.py` — wraps the `bws` CLI. Never call `bws` directly from other modules; go through `BwsResolver`.
- `src/keyholderd/peercred.py` — `SO_PEERCRED` → uid → username. Authentication for every request.
- `src/keyholderd/providers/` — one file per credential type (`github_app.py`, `aws_sts.py`, `local_proxy.py`, `fake.py`). New providers implement the `Provider` protocol in `base.py`.
- `packaging/` — systemd service unit, sysusers fragment, `install.sh`, and example policy. `packaging/policy.local.yaml` is gitignored and holds the real deployed policy on this machine.
- `tests/` — pytest suite; each source module has a matching `test_*.py`.

## Development workflow

```bash
uv venv                       # once
uv pip install -e '.[test]'   # once
uv run pytest -q              # run tests
```

The suite must stay green (`54 passed`) before commits. If you add functionality, add tests for it in the same commit.

## Deployment notes for this host

- Deployed as a systemd service. Binaries in `/usr/local/bin/keyholder{,d}`, venv at `/opt/keyholder/venv`, policy at `/etc/keyholder/policy.yaml`, encrypted BWS token at `/etc/keyholder/bws-access-token.cred`, socket at `/run/keyholder/keyholder.sock`, leases at `/var/lib/keyholder/leases.db`, audit log at `/var/log/keyholder/audit.jsonl`.
- After editing source, reinstall with `sudo packaging/install.sh` — the canonical reinstall/upgrade path. It reinstalls the package into the existing venv and restarts the service; it never touches an existing `policy.yaml` or `.cred` file, so it's safe to re-run on this live host. Equivalent by hand: `sudo /opt/keyholder/venv/bin/pip install --force-reinstall --no-deps .` then `sudo systemctl restart keyholder.service`.
- After editing `packaging/policy.local.yaml`, copy it to `/etc/keyholder/policy.yaml` and restart the service (no hot-reload yet). `install.sh` will not do this for you — it only installs the example policy, and only if none exists.
- After editing `packaging/keyholder.service`, `sudo packaging/install.sh` reinstalls the unit and reloads/restarts, or by hand: reinstall to `/etc/systemd/system/`, `daemon-reload`, then restart.
- The caller Unix user must be a member of the `keyholder-clients` group to reach the socket. New shells inherit the group; existing shells need `newgrp keyholder-clients` or a re-login. Run `keyholder doctor` to check this and everything else end-to-end.

## Constraints and conventions

- Never commit real IDs, secrets, or the encrypted `.cred` file. Real values go in `packaging/policy.local.yaml` (gitignored) and `/etc/keyholder/`.
- Never bypass the audit layer when introducing a new code path that mints or forwards credentials.
- Never widen an existing grant to add unrelated permissions. Create a new grant with the narrower purpose.
- Prefer editing existing modules to introducing new ones; the codebase is deliberately small.
- Match the existing style: `from __future__ import annotations` at the top of every module, dataclasses for value types, minimal comments (only when the "why" is non-obvious).
