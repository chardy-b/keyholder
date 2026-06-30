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

Suggested Loki queries:

```logql
{job="keyholder", level="ERROR"}
{filename="/var/log/keyholder/audit.jsonl"} | json | event="run"
```
