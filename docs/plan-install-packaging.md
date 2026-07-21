# Plan: simplify install and replication

Goal: shrink the install from ~15 hand-run sudo commands to one script (and eventually
one `.deb`), and add a `keyholder doctor` command so a new host can self-diagnose.
This plan is a handoff document — implement the work items in order, one commit each,
keeping the pytest suite green throughout.

Read `CLAUDE.md` and `README.md` first. Constraints that apply to everything below:

- Never commit real IDs, secrets, or `.cred` files. `packaging/policy.local.yaml` is
  gitignored and must stay that way.
- This host is a **live deployment** of keyholder (see "Deployment notes" in CLAUDE.md).
  The install script must be safe to run on it: idempotent, and it must **never
  overwrite** an existing `/etc/keyholder/policy.yaml` or
  `/etc/keyholder/bws-access-token.cred`.
- Match existing code style: `from __future__ import annotations`, dataclasses,
  minimal comments.
- `README.md` and `CLAUDE.md` both cite the test count ("30 passed" / "30 tests");
  update those numbers when you add tests.

---

## Work item 1: `packaging/keyholder.sysusers.conf`

Declarative user/group creation via systemd-sysusers, replacing the manual
`groupadd`/`useradd` steps in README §2.

```
u keyholder - "keyholder token broker" /var/lib/keyholder /usr/sbin/nologin
g keyholder-clients -
m keyholder keyholder-clients
```

Notes:

- The install script (item 2) copies this to `/etc/sysusers.d/keyholder.conf` and runs
  `systemd-sysusers /etc/sysusers.d/keyholder.conf`. The `.deb` (item 6) will ship it in
  `/usr/lib/sysusers.d/`.
- `/var/lib/keyholder`, `/var/log/keyholder`, and `/run/keyholder` are already created
  by `StateDirectory=`/`LogsDirectory=`/`RuntimeDirectory=` in the service unit — do
  **not** add tmpfiles entries for them. Only `/etc/keyholder` needs explicit creation
  (the install script does it; no tmpfiles fragment needed).
- Adding the *caller* user to `keyholder-clients` is per-host operator choice, not part
  of the fragment — the install script handles it via a flag (item 2).

## Work item 2: `packaging/install.sh`

One idempotent script covering README Installation §§1–4. Also serves as the upgrade
path: re-running after `git pull` reinstalls the package and restarts the service.

Usage:

```
sudo packaging/install.sh [--client-user USER] [--bws-token-file PATH] [--no-start]
```

Steps, in order:

1. **Preflight** (fail early with a clear message per check):
   - running as root; `systemctl --version` ≥ 254; `python3` ≥ 3.11; `bws` on `PATH`.
   - repo root detected from the script's own location (`$(dirname "$0")/..`), so it
     works from any CWD.
2. **Users/groups**: install `keyholder.sysusers.conf` to `/etc/sysusers.d/` and run
   `systemd-sysusers`. If `--client-user` given, `usermod -aG keyholder-clients USER`
   and print the "new shells only / `newgrp`" warning.
3. **Config dir**: `install -d -o root -g keyholder -m 0750 /etc/keyholder`.
   (This must come *after* step 2 — the current README has these in the wrong order,
   referencing the `keyholder` group before creating it. The script fixes that bug.)
4. **BWS credential** — skip entirely if `/etc/keyholder/bws-access-token.cred` exists
   (print "already present, leaving alone"). Otherwise:
   - with `--bws-token-file PATH`: `systemd-creds encrypt --name=bws-access-token PATH …`
   - else prompt interactively (`read -rs`) and pipe to `systemd-creds encrypt … -`.
   - `chown root:keyholder`, `chmod 0640` the result.
   - Print a prominent note: **this file is sealed to this host's key/TPM and cannot be
     copied between machines** — every host runs this step itself.
5. **Venv install**: create `/opt/keyholder/venv` if missing
   (`python3 -m venv /opt/keyholder/venv`), then always
   `pip install --upgrade pip` and `pip install --force-reinstall --no-deps <repo>`
   (deps installed normally on first run: plain `pip install <repo>` when the venv is
   fresh; `--force-reinstall --no-deps <repo>` when upgrading, matching the CLAUDE.md
   upgrade recipe). Then `install -m 0755` the two entry points to
   `/usr/local/bin/keyholder{,d}`.
6. **Unit + policy**: `install -m 0644 packaging/keyholder.service /etc/systemd/system/`;
   install `packaging/policy.example.yaml` to `/etc/keyholder/policy.yaml`
   (`-m 0640 -o root -g keyholder`) **only if no policy exists** — never clobber.
   `systemctl daemon-reload`.
7. **Start**: unless `--no-start`, `systemctl enable --now keyholder.service` (or
   `systemctl restart` if already active). Then run
   `/usr/local/bin/keyholder doctor` (item 3) and surface its output — but if a fresh
   example policy was just installed, remind the operator to edit it and restart before
   expecting `grants` to work.

Style: `set -euo pipefail`, small functions, `log()`/`die()` helpers, no color codes
required. Every mutating step prints what it did or "already done, skipped".

Verification: run it on this host (it is already deployed — the run must be a clean
no-op except for the pip reinstall + restart) and confirm `keyholder grants` still
works afterward from a `keyholder-clients` shell.

## Work item 3: `keyholder doctor` subcommand

New subcommand in `src/keyholderd/cli.py` that checks a host end-to-end and prints one
line per check: `ok` / `warn` / `fail` plus a short hint on failure. Exit 0 if nothing
failed, 1 otherwise. `--socket` is respected like the other subcommands.

Checks, in order:

1. **systemd version** ≥ 254 (parse `systemctl --version` first line; `warn` if
   systemctl missing — might be a dev box).
2. **bws on PATH** (`shutil.which`). `warn` not `fail` if missing when the daemon is
   remote-in-principle; keep it simple: `fail` if the service unit exists on this host,
   `warn` otherwise.
3. **Service active**: `systemctl is-active keyholder.service` → `fail` with hint
   `journalctl -u keyholder.service` if not.
4. **Socket**: exists at the socket path, is a socket (`stat.S_ISSOCK`), mode `0660`,
   group `keyholder-clients`.
5. **Group membership**: distinguish *configured* membership
   (`getent`-equivalent via `grp.getgrnam("keyholder-clients").gr_mem` + primary gid)
   from *active* membership (`os.getgroups()`). Configured-but-not-active gets a
   dedicated hint: "run `newgrp keyholder-clients` or re-login" — this is the single
   most common trap.
6. **Config present**: `/etc/keyholder/policy.yaml` exists. Parse it with
   `load_policy` **only if readable**; the file is root:keyholder 0640, so a normal
   caller can't read it — in that case print `ok (unreadable by this user, skipped
   parse)`. Do not require sudo.
7. **Credential file**: `/etc/keyholder/bws-access-token.cred` exists. Attempt
   `systemd-creds decrypt` only when running as root (`warn: run with sudo to verify
   decryption` otherwise); when root, pipe to `/dev/null` — never print any part of
   the plaintext.
8. **End-to-end**: `GET /v1/grants` over the socket using the existing `request()`
   helper. Report the number of grants, not their contents.

Implementation notes:

- Keep it dependency-free (stdlib only), consistent with the rest of the CLI.
- Structure as a list of `(name, check_fn)` pairs so tests can call check functions
  individually; each returns a small result dataclass (`status`, `detail`).
- **Do not** write audit events from doctor itself; the daemon already audits the
  `grants` call it triggers.
- Tests in `tests/test_cli.py` (or a new `tests/test_doctor.py` matching the
  one-file-per-module convention): unit-test individual checks with monkeypatched
  `shutil.which`/`os.getgroups`/`subprocess.run`, and one test driving `main(["doctor"])`
  against the fake-provider test server fixture used by the existing e2e test.

## Work item 4: README + CLAUDE.md rewrite of the install story

- README "Installation" collapses to: prerequisites, then

  ```bash
  git clone … && cd keyholder
  sudo packaging/install.sh --client-user "$USER"
  keyholder doctor
  ```

  Keep the current manual steps in a collapsed `<details>` block titled "Manual
  install (what the script does)" — they document the mechanism and remain the
  reference for the `.deb` postinst.
- Document `keyholder doctor` in the CLI section.
- Add an "Upgrading" subsection: `git pull && sudo packaging/install.sh` (or the
  existing pip one-liner).
- Add a "Replicating to another machine" subsection covering the two host-specific
  artifacts that cannot be copied: the policy (edit per host) and the `.cred` file
  (host-sealed; re-encrypt on each machine).
- Update CLAUDE.md deployment notes to point at `install.sh` as the canonical
  reinstall path, and refresh the test count.

## Work item 5: versioning and installability from git

- Add `CHANGELOG.md` (Keep a Changelog format) with `0.1.0` covering everything to
  date and an `Unreleased` section for items 1–4.
- After items 1–4 land, bump `pyproject.toml` to `0.2.0`, finalize the changelog,
  commit, and tag `v0.2.0` (annotated tag). Do not push tags unless asked.
- README gains a note that the package installs from a checkout or from git
  (`pip install git+<url>@v0.2.0`) — no PyPI publication in this plan.

## Work item 6: `.deb` package via nfpm

Do this **last** — the postinst logic is exactly what `install.sh` proves out.

- `packaging/nfpm.yaml`:
  - package `keyholder`, arch `amd64`, depends: `python3 (>= 3.11)`, `systemd (>= 254)`.
  - contents: `keyholder.service` → `/usr/lib/systemd/system/`,
    `keyholder.sysusers.conf` → `/usr/lib/sysusers.d/keyholder.conf`,
    `policy.example.yaml` → `/usr/share/keyholder/policy.example.yaml`,
    built wheels (see below) → `/usr/share/keyholder/wheels/`.
  - scripts: `packaging/deb/postinst`, `packaging/deb/prerm`, `packaging/deb/postrm`.
- `packaging/build-deb.sh`: builds the project wheel plus all dependency wheels into a
  staging dir (`pip wheel . -w staging/wheels`), then runs `nfpm package -p deb`.
  Requires `nfpm` on PATH; `die` with an install pointer if absent. Wheels are bundled
  so postinst needs no network access.
- `postinst`: `systemd-sysusers`; create venv at `/opt/keyholder/venv` if missing;
  `pip install --no-index --find-links /usr/share/keyholder/wheels local-keyholder`;
  symlink entry points into `/usr/local/bin` (a deb shouldn't `install` into
  `/usr/local`, but symlinks keep parity with the script install; alternatively place
  real files in `/usr/bin` via nfpm contents if the venv shebang approach allows —
  implementer's choice, document it); create `/etc/keyholder`; copy example policy
  only if absent; `daemon-reload` + `enable`. Print instructions for the two manual
  per-host steps (BWS credential encryption, client-user group add) instead of doing
  them — a package must not prompt.
- `prerm`/`postrm`: stop/disable on remove; leave `/etc/keyholder`, `/var/lib`, and
  logs in place on remove, delete only on purge (and even on purge, keep the `.cred`
  and print a note — deleting credentials silently is hostile).
- Verify: build the deb, install it in a fresh container or VM if available
  (`debian:bookworm` has systemd ≥ 252 — use `ubuntu:24.04`+ or `debian:trixie` for
  ≥ 254), or at minimum `dpkg-deb --contents` and lint the scripts with `sh -n` and
  `shellcheck` if installed.

---

## Order and commit plan

| # | Commit | Contents |
|---|--------|----------|
| 1 | `feat: add sysusers fragment and idempotent install script` | items 1 + 2 |
| 2 | `feat: add keyholder doctor subcommand` | item 3, with tests |
| 3 | `docs: collapse install instructions to install.sh + doctor` | item 4 |
| 4 | `chore: add changelog, bump to 0.2.0` | item 5 (+ tag) |
| 5 | `feat: build a .deb via nfpm` | item 6 |

## Acceptance criteria

- `uv run pytest -q` green at every commit; doctor checks have unit tests.
- `sudo packaging/install.sh` on this (already-deployed) host completes as an
  effective no-op upgrade: no prompt for the BWS token, policy untouched, service
  restarted, `keyholder doctor` all-`ok` afterward from a group-active shell.
- A fresh-host walkthrough exists in the README and consists of ≤ 3 commands plus
  editing the policy.
- `packaging/build-deb.sh` produces an installable `.deb` whose postinst never
  prompts and never overwrites existing config.
