# local-keyholder

Local Unix-socket token broker for Hermes. It authenticates callers via Unix peer credentials, checks a YAML policy, resolves long-lived secrets through Bitwarden Secrets Manager (`bws`), and mints/brokers short-lived credentials.

## Security model

- Hermes never reads Bitwarden or long-lived provider secrets directly.
- Local authorization is based on Linux username from `SO_PEERCRED`.
- Prefer `keyholder run` so tokens are injected only into a child process environment.
- Audit logs reject secret-like fields and never include token values.
- Static upstream API keys use `local_proxy` capability tokens rather than exposing upstream keys.

## Development

```bash
uv venv
uv pip install -e '.[test]'
uv run pytest -v
```

## CLI

```bash
keyholder grants
keyholder issue github-readonly --ttl 300 --reason "Need temporary GitHub token" --format json
keyholder run github-readonly --env GITHUB_TOKEN --ttl 300 --reason "Inspect repo" -- gh repo view OWNER/REPO --json name
keyholder revoke lease_...
```

## Installation sketch

```bash
sudo useradd --system --home /var/lib/keyholder --shell /usr/sbin/nologin keyholder
sudo groupadd --system keyholder-clients
sudo usermod -aG keyholder-clients hermes
sudo install -d -o root -g keyholder -m 0750 /etc/keyholder
sudo install -d -o keyholder -g keyholder -m 0700 /var/lib/keyholder
sudo install -d -o keyholder -g adm -m 0750 /var/log/keyholder
sudo install -m 0640 -o root -g keyholder packaging/policy.example.yaml /etc/keyholder/policy.yaml
sudo install -m 0755 .venv/bin/keyholder /usr/local/bin/keyholder
sudo install -m 0755 .venv/bin/keyholderd /usr/local/bin/keyholderd
sudo install -m 0644 packaging/keyholder.service /etc/systemd/system/keyholder.service
```

Create the encrypted systemd credential outside Hermes:

```bash
sudo systemd-creds encrypt --name=bws-access-token - /etc/keyholder/bws-access-token.cred
```

Then enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now keyholder.service
```

## Grafana logging

`keyholderd` logs structured JSON to stdout/stderr for journald collection by Grafana Alloy/Promtail. See [`docs/grafana-logging.md`](docs/grafana-logging.md). The append-only audit JSONL file is `/var/log/keyholder/audit.jsonl`.

## Hermes usage

See [`docs/hermes-usage.md`](docs/hermes-usage.md).
