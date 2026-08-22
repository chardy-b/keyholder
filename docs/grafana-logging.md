# Grafana / Loki logging

`keyholderd` emits structured JSON log lines to stdout/stderr. Under systemd these land in journald and can be scraped by Grafana Alloy/Promtail into Loki.

Recommended Alloy snippet:

```river
loki.source.journal "keyholder" {
  matches    = "_SYSTEMD_UNIT=keyholder.service"
  labels     = { job = "keyholder", host = constants.hostname }
  forward_to = [loki.process.keyholder.receiver]
}

loki.process "keyholder" {
  stage.json {
    expressions = {
      level  = "level",
      logger = "logger",
      msg    = "msg",
    }
  }
  stage.labels {
    values = { level = "level", logger = "logger" }
  }
  forward_to = [loki.write.default.receiver]
}
```

Audit events are append-only JSONL at `/var/log/keyholder/audit.jsonl`; configure a separate file target if you want searchable audit records. Secret-like fields are rejected before writes, and provider token values are never sent to the audit log.

For the peer-credential OpenRouter socket, monitor `proxy_attempt`, successful
completion, rejection, and failure events together with daemon request/latency
logs. These are operational signals only: caller identity, grant, route,
status, and timing may be recorded, but capabilities, model payloads, and
upstream keys must not appear. A missing socket, permission failure, or daemon
restart should be treated as fail-closed availability rather than a reason to
fall back to copying an upstream key into Hermes.

Suggested Loki queries:

```logql
{job="keyholder", level="ERROR"}
{filename="/var/log/keyholder/audit.jsonl"} | json | event="run"
```
