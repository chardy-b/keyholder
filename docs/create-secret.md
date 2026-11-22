# Isolated, opt-in secret creation

```sh
keyholder create-secret --grant hermes-generated --key HERMES_EXAMPLE \
  --reason 'Provision example' -- openssl rand -hex 32
```

The CLI runs the trusted generator **locally as the caller**, without a shell.
It discards stdin/stderr, privately captures stdout in memory, and terminates
the generator process group on overflow or a fixed 10-second total deadline.
No request is sent unless the generator exits successfully. The hard stdout
limit is 4096 bytes **before** removing exactly one final LF (unless `--raw`).
The resulting value must be nonempty UTF-8 without NUL. CR, other whitespace,
and embedded newlines are preserved. This is a text-secret interface, not a
binary-file uploader. The generator must not leak by its own side effects.

The value is sent only in the body of an authenticated local Unix-socket
request, never in arguments, environment, files, audit, or terminal output.
Do not use shell substitution, secret literals in generator arguments, or
secrets in `--reason`. The free-form reason is validated but deliberately
**not persisted**, including in the Bitwarden note (which is constant).
Output is only JSON `{ "id": "<new UUID>", "key": "HERMES_EXAMPLE" }` or a
fixed error; raw responses and exception details are never printed.
No automatic retry or deletion is performed after ambiguous writes.

## Why a separate service is mandatory

The ordinary daemon's `/v1/run` executes arbitrary caller-supplied commands as
its **own** OS user, `keyholder`. A write credential loaded into that service,
or readable by that UID, is therefore readable by every generic run grantee.
**Never add a write credential or writer drop-in to `keyholder.service`.**

The maintained [writer unit](../packaging/keyholder-secret-writer.service) runs
as its own user **and primary group**, `keyholder-secret-writer`, with a distinct
credential directory, root-managed policy, socket and audit directory. Its
`--secret-writer-only` mode dispatches only `POST /v1/create-secret`: no grants,
issue, run, revoke or Grafana operations, and no proxy listener even if policy
accidentally enables one. Writer startup refuses root or the `keyholder` user.
The normal daemon does not expose create-secret. Do not co-host other command
execution under the writer UID or grant the main daemon membership in the
writer group. `keyholder` peer requests are always denied, even if a policy
entry mistakenly includes them.

`keyholder-clients` only permits reaching the socket; it does **not** authorize
creation. Each request still uses kernel `SO_PEERCRED` username → configured
profile → named `secret_creates` entry. These entries are separate from ordinary
`grants`, so they cannot be issued or run. The daemon fixes project and uppercase
key prefix in policy; it accepts no project, credential or command from a client.

The create CLI defaults to `/run/keyholder-secret-writer/keyholder.sock`, not the
main socket and not ambient `KEYHOLDER_SOCKET`. An explicit global
`--socket PATH` before `create-secret` is the only override. Only point it to an
operator-controlled writer socket: it receives the generated value.

## Operator installation (not automatic)

Existing installs and `packaging/install.sh` are unchanged. These are reference
commands for an operator, **not** a deployment performed by this patch. Install
the updated Python package into the existing root-managed `/opt/keyholder/venv`
and entry points first (see README); do not start either service merely to test
this feature. The pinned Bitwarden SDK is used in-memory, not the `bws` CLI.

1. Review and install the separate sysusers file, then create only its identity:

   ```sh
   sudo install -m 0644 packaging/keyholder-secret-writer.sysusers.conf /etc/sysusers.d/
   sudo systemd-sysusers /etc/sysusers.d/keyholder-secret-writer.sysusers.conf
   sudo install -d -o root -g keyholder-secret-writer -m 0750 /etc/keyholder-secret-writer
   sudo install -o root -g keyholder-secret-writer -m 0640 \
     packaging/secret-writer.policy.example.yaml /etc/keyholder-secret-writer/policy.yaml
   ```

2. Edit the separate policy: replace the synthetic UUIDs and `example-agent`
   username, select the smallest dedicated project, and keep the narrow prefix.
   The example contains no real IDs or credentials. Do not authorize `keyholder`.
   The caller also needs membership in `keyholder-clients` (new login required).

3. Provision a **separate project-scoped Bitwarden machine account** with
   **read/write** permission for that destination only. Bitwarden privilege is
   not truly create-only: the account can read/write the project. Create-only
   behavior is a service-specific policy boundary; compromising this writer UID
   or credential compromises that project. Do not reuse the normal read token.
   Encrypt it interactively without printing it or creating a plaintext file:

   ```sh
   set -o pipefail
   systemd-ask-password 'Writer machine-account token:' | \
     sudo systemd-creds encrypt --name=bws-create-access-token - \
       /etc/keyholder-secret-writer/bws-create-access-token.cred
   sudo chown root:root /etc/keyholder-secret-writer/bws-create-access-token.cred
   sudo chmod 0600 /etc/keyholder-secret-writer/bws-create-access-token.cred
   ```

   The writer reads only `CREDENTIALS_DIRECTORY/bws-create-access-token`. Missing
   credentials fail closed; no fallback to `bws-access-token`,
   `BWS_ACCESS_TOKEN_FILE`, or an ambient access token. Systemd supplies the
   credential under this **separate service's** private credential directory.
   Never loosen its permissions or share that directory with the main daemon.

4. Install the unit for deliberate operator activation (not auto-enabled):

   ```sh
   sudo install -m 0644 packaging/keyholder-secret-writer.service /etc/systemd/system/
   sudo systemctl daemon-reload
   # Only after independent permission/policy review and authorization:
   sudo systemctl start keyholder-secret-writer.service
   ```

   The writer owns `/run/keyholder-secret-writer` and
   `/var/log/keyholder-secret-writer` (audit directory mode 0750, files 0600).
   Socket mode 0660, group `keyholder-clients`; the writer needs that supplementary
   group to chgrp its socket. Verify the regular daemon cannot read the writer's
   policy, credential or audit files and has no writer-group membership.
   No live credential or Bitwarden test is required for the synthetic test suite.

## Create-only behavior and limits

The daemon rejects existing exact keys in the destination before fetching their
values: even an identical value conflicts, so there is no equality oracle.
It never updates/deletes. A successful create is read back and checked for exact
value and ID/key/project/organization before returning metadata. Pre-create
lookup/auth/policy failures say nothing was written. A create/readback failure,
worker loss or timeout says the secret **may exist**; check through an approved
operator workflow before retrying. Do not assume timeout means cancellation.

A durable metadata-only attempt audit is required before write. Outcomes record
fixed reason codes and policy metadata, never the input key, value or free-form
reason. The SDK runs in a short-lived, output-suppressed worker, killed/reaped at
a 60-second total deadline; IPC replies are bounded and strictly validated.
The daemon reads at most 32768 JSON body bytes in 5 seconds, rejects duplicate
fields, unknown fields and ambiguous HTTP framing. The Unix server serializes
requests, plus a create lock. This is **not an atomic global uniqueness guarantee**:
Bitwarden has no key uniqueness constraint; external writers or another service
instance can race the list/create. Use a dedicated project and a single writer
instance. A post-write audit failure can leave only the durable attempt record.

This prevents accidental transcript/log exposure, not inspection by root,
ptrace-capable processes, or processes sharing the caller/writer UID. Python
strings are not securely erased. Trusted generators and the CLI must run in an
appropriately protected caller environment; the unit disables core dumps.
