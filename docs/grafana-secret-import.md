# Grafana credential import

A fixed-purpose broker operation that copies the **existing** Grafana admin
password from the Matrix host into Bitwarden Secrets Manager (not a personal
vault). It does not rotate, update, delete, or overwrite anything.

| Fixed by code (callers cannot change) | Value |
| --- | --- |
| Source | `root@matrix-ubuntu:/opt/fleet-observability/secrets/grafana_password` (must already exist) |
| Destination key | `GRAFANA_FLEET_ADMIN_PASSWORD` |
| Destination project | one canonical UUID pinned in operator policy (import is disabled until set) |

Two authenticated Unix-socket actions, no request fields except an optional
`profile`:

- `POST /v1/grafana-projects` / `keyholder grafana-projects` — lists the `id` and
  `name` of projects the broker's machine account can access (`bws project list`,
  via `BwsResolver`). Metadata only; works before a project is selected.
- `POST /v1/grafana-import` / `keyholder grafana-import` — reads the source,
  creates the secret if absent, verifies by readback, and returns only
  `{"id", "key", "project_id", "status_verified": true}`.

## Behaviour

1. Framing and schema. The body is read only after the peer-credential caller
   is known, under a 5 s **total** deadline (a trickled or missing body does not
   extend it), with a single numeric `Content-Length` of at most 1024 bytes;
   duplicate `Content-Length`, any `Transfer-Encoding`, or a non-decimal length
   is rejected. The body must be JSON with no unknown or duplicate fields. All
   rejections are `400 invalid request`, audited as `denied/invalid_request`
   without echoing any content, and happen before any source or Bitwarden call.
2. Caller → `operations` authorization (below) → import config validation (fails
   closed) → one-at-a-time lock held by the request → **durable (fsynced)
   `attempt` audit event; if it cannot be written, nothing else happens**.
3. Everything with a secret or token runs in a **short-lived forked worker
   process** (Linux only), never in a daemon thread. The worker moves into its
   own process group, redirects stdout/stderr (including native SDK output) to
   `/dev/null`, closes every inherited descriptor except its reply pipe (so the
   HTTP socket and audit handles are not shared), clears `RUST_LOG`, sets an
   alarm slightly beyond the deadline as a self-limit, reads the source, runs the
   Bitwarden SDK work, and writes **only** sanitized metadata or a fixed error
   code to a private pipe: no value, hash, or token ever crosses to the daemon.
   The parent validates the reply against an exact schema (including that
   key/project match the policy) and treats anything else as `worker_failed`.
   At the absolute 60 s deadline the parent kills the worker's process group
   (which also contains ssh), reaps it, releases the lock, and records exactly
   one `failed/timeout` event; there is no late completion event because the
   worker is dead. The `504` message says a write may already exist and to retry,
   since retry resolves through the dedup step.
4. Source read inside the worker over `/usr/bin/ssh` with a fixed argv (see
   [prerequisites](#deployment-prerequisites-parent-only)): `BatchMode=yes`,
   `StrictHostKeyChecking=yes`, pinned `UserKnownHostsFile`, `-F /dev/null`, no
   forwarding/agent, remote command `head -c 4097 -- <fixed path>`. The child
   environment is exactly `PATH` and `LANG`: no Bitwarden token, no credential
   paths, no agent socket. stdout is read into memory with a 20 s deadline and a
   hard 4096-byte cap (ssh is killed on overflow); stderr is discarded. The
   value must be non-empty, valid UTF-8, with no NUL.
5. Value semantics: the bytes are retained **exactly**. A trailing newline is
   part of the value unless the operator sets
   `strip_single_trailing_newline: true`, which removes exactly one final LF
   (`\n`, byte `0x0a`) if the value ends with one, and nothing else. A value
   ending in several LFs loses only the last; a CRLF-terminated value loses the LF
   and keeps the CR. Choose it only after checking how the file was written; the
   choice also defines what "identical" means for dedup.
6. Bitwarden, all inside `BwsResolver` using `bitwarden-sdk==2.1.0` in the worker's
   memory (token read from `BWS_ACCESS_TOKEN_FILE` inside the broker; login
   without a state file, so nothing is written to disk; the secret value is never
   put in argv — `bws secret create VALUE` is not used):
   - `projects.get(<pinned id>)` confirms access and yields the organization.
   - `secrets.list(org)`; records whose key is exactly the destination key **and**
     whose project list contains the pinned project are the candidates. Same key
     in another project is ignored and never touched.
   - 0 candidates → `secrets.create(...)` with `project_ids=[pinned]`, then
     `secrets.get(new id)` and exact comparison of id/key/project/organization/value.
   - 1 candidate → `secrets.get(id)`; identical value → returns it (`status_verified`);
     different value → `409`, nothing changes. There is no update option.
   - more than 1 candidate → `409`, fail closed.
   - A create whose readback fails or mismatches is reported as
     `write_ambiguous` (`502`); the record is **not** rolled back or deleted. Retry:
     the dedup step finds it and verifies.
7. Completion or failure audit event (fixed reason codes only), written by the
   parent after the worker is reaped.

Second invocation after success makes no create call and returns the same output.

Errors returned to clients and written to audit are fixed strings from a table in
`grafana_import.py` (e.g. `source read failed`, `value differs … explicit
approval required`); SDK, SSH, and token exception text is never forwarded,
logged, or kept in an exception chain.

## Audit events

`event`/`operation` is `grafana_projects` or `grafana_import`; `phase` is
`denied`, `attempt`, `completed`, or `failed`; `reason` is a fixed code
(`invalid_request`, `not_authorized`, `not_configured`, `busy`, `attempt`,
`created`, `already_present`, `listed`, `timeout`, `worker_failed`, or an error code). Extras:
`project_id` (pinned), `record_id`, `project_count`. No values, hashes, tokens,
or caller-supplied text.

## Authorization

Operations are authorized by a new `operations` list on a profile, **separate
from `grants`**. `issue`/`run` only consult `grants`, and operation names are not
grants, so neither can reach these actions (tested). Entries accept exactly
`operation` and `expires_at` (timezone-aware ISO-8601, quoted; checked on every
request). `grafana_import` **requires** an `expires_at` deadline; metadata
listing may omit it. Malformed entries grant nothing.

## Policy fragments (placeholders only)

Merge these into the **existing** `packaging/policy.local.yaml` /
`/etc/keyholder/policy.yaml`; do not replace the file, and preserve every
unrelated grant. `operations:` sits next to the existing `grants:` list inside
the caller's profile. Never commit real IDs.

Step 1 — metadata only (no import config, import stays disabled):

```yaml
callers:
  hermes:                       # existing caller entry
    profiles:
      default:                  # existing profile
        grants: []              # existing grants stay exactly as they are
        operations:
          - operation: grafana_projects
```

Step 2 — after the parent picks the destination project:

```yaml
grafana_import:                 # new top-level key
  enabled: true                 # must be the YAML boolean true
  project_id: "<canonical-lowercase-project-uuid>"
  # organization_id: "<canonical-lowercase-org-uuid>"   # optional extra pin
  # strip_single_trailing_newline: true                  # optional, see above

callers:
  hermes:
    profiles:
      default:
        operations:
          - operation: grafana_projects
          - operation: grafana_import
            expires_at: "<ISO-8601 timestamp with timezone, e.g. a few hours ahead>"
```

`project_id` / `organization_id` must be canonical lowercase hyphenated UUIDs
and not the all-zero placeholder, `enabled` must be the literal `true`, and
unknown keys are rejected; anything else answers `503 grafana import is not
configured`. Remove the `grafana_import` operation entry (or let it expire) when
done. The daemon loads policy only at startup — restart after edits.

### Organization ID (parent decision recorded)

The organization is **inferred** from the pinned project via the SDK
(`projects.get`), so no organization UUID is needed to bootstrap. If you add
`organization_id`, the project's organization must equal it or the import stops
(`project_mismatch`) before any secret call. It is an optional extra guard.

## Deployment prerequisites (parent only)

None of this was exercised live. The service sandbox is unchanged.

1. **Machine account access**: the Bitwarden machine account behind
   `/etc/keyholder/bws-access-token.cred` needs **read + write** on the chosen
   destination project (set in the Secrets Manager UI). Read-only is enough for
   `grafana-projects` but not for the import.
2. **Host key pin**: a root-managed file at
   `/etc/keyholder/grafana-import-known_hosts` containing a `matrix-ubuntu
   <keytype> <public key>` line obtained through a trusted channel. The daemon
   refuses to run ssh unless it is a regular file (not a symlink), owned by uid 0,
   non-empty, and not group/world writable (e.g. `root:keyholder 0640`). The
   daemon user has `ProtectHome=true` and cannot use Hermes' `~/.ssh` state, so
   this dedicated file is the only host-key source (`GlobalKnownHostsFile` is
   `/dev/null`; `StrictHostKeyChecking=yes`, never `no`/`accept-new`).
3. **Tailscale SSH**: no SSH credentials are configured or changed. The
   existing Tailscale SSH policy must already let this node connect as `root` to
   `matrix-ubuntu` non-interactively (`BatchMode=yes` cannot complete a
   check-mode browser approval). Note the ssh client runs as the `keyholder`
   user; if node/user authorization depends on anything per-UID, that must be
   arranged by the operator — not assumed here.
4. **Install**: from the clean, already-prepared checkout run
   `sudo packaging/install.sh`. On an existing venv it keeps `--no-deps` for the
   package and additionally runs `pip install "bitwarden-sdk==2.1.0"` (pin kept in
   sync with `pyproject.toml`, which a test checks), so only the SDK and its tiny
   dependency tree are added. Deployment is not a Git operation: no `git` as root,
   no fetch/switch/reset.
5. Add the policy fragments above to the deployed policy, restart, then:
   `keyholder grafana-projects` → choose the project → add step 2 → restart →
   `keyholder grafana-import` → run it a second time and confirm identical output
   (no new secret) → drop the operation entry.

## Validation record

Python 3.12 venv outside the repo (`bitwarden-sdk==2.1.0`, `pytest`, runtime
deps). The package is not installed in that venv; `tests/conftest.py` adds `src`
to `sys.path` only inside pytest, so the proxy worker subprocesses need
`PYTHONPATH` to import `keyholderd`. No network credentials, ssh, `bws`, or
keyholder-socket use.

```
$ PYTHONPATH="$PWD/src" python -m pytest -q -p no:cacheprovider \
      --basetemp=/mnt/HC_Volume_106820083/artifacts/keyholder/gi-tests1
307 passed
$ uv lock --check          # ok
$ git diff --check         # ok
```

A short `--basetemp` is needed because pytest's default temp paths under this
host's long `TMPDIR` exceed the `AF_UNIX` path limit for two older socket tests;
without `PYTHONPATH` two `test_proxy.py` tests fail with `ModuleNotFoundError`.
With both set the whole suite is green.

New suites: `test_bitwarden_import.py` (real SDK client/JSON protocol and
response models over a stubbed native layer), `test_grafana_import.py`,
`test_grafana_import_worker.py` (real forked worker: deadline kill with no late
write or audit, descendant kill, lock release, output suppression, descriptor
and `RUST_LOG` hygiene, reply-schema validation), `test_grafana_import_e2e.py`
(Unix-socket server + CLI, an in-process-worker path with mocked bws/SDK/source, a
real-forked-worker path with file-shared fake Bitwarden state, and raw-socket
framing/body-deadline cases), `test_install_script.py`. Most other tests use an
in-process stand-in for the worker (autouse fixture in `tests/conftest.py`) so
mocks stay observable. Also checked: importing the SDK and constructing a client
works under `PR_SET_MDWE` (the kernel analogue of the unit's
`MemoryDenyWriteExecute=true`).

### Not live-verified (explicit gates before relying on this)

- Real Bitwarden: SDK login with the machine token, `projects.get`,
  `secrets.list`/`create`/`get` for a machine account (including that `list`
  returns project IDs and write permission applies), default US cloud endpoints
  (matching the existing `bws` usage; EU would need endpoint settings).
- The SDK network login inside the real `keyholder.service` sandbox
  (`MemoryDenyWriteExecute`, `RestrictAddressFamilies`); only import/construct was
  checked.
- The ssh path: Tailscale SSH authorization for the `keyholder` UID, the pinned
  host key file, and the actual remote `head` output.
- The source file's real trailing-newline convention
  (`strip_single_trailing_newline`).
- Behaviour of `bws project list` output fields in the installed `bws` version.
- The single-threaded socket server blocks other requests while an import runs
  (bounded by the 20 s ssh and 60 s operation deadlines). `fork()` is used from a
  process that may also run the optional proxy listener thread; the worker only
  runs straight-line code and exits with `os._exit`, but this was only exercised
  in tests, not in the live service.
