# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-07-20

### Added

- `packaging/keyholder.sysusers.conf` — declarative user/group creation via
  `systemd-sysusers`, replacing manual `groupadd`/`useradd` steps.
- `packaging/install.sh` — one idempotent install/upgrade script covering
  preflight checks, users/groups, config directory, BWS credential
  encryption, venv install, unit + policy install, and service start. Never
  overwrites an existing `policy.yaml` or `bws-access-token.cred`.
- `keyholder doctor` — end-to-end host self-diagnosis: systemd version, `bws`
  on `PATH`, service state, socket permissions, group membership (configured
  vs. active session), policy and credential presence, and a live
  `GET /v1/grants` round trip. Exits non-zero if any check fails.

### Changed

- README Installation section collapses to a 3-command quickstart
  (`git clone`, `sudo packaging/install.sh`, `keyholder doctor`); the
  original manual steps remain in a collapsed reference section.
- CLAUDE.md deployment notes point at `install.sh` as the canonical
  reinstall/upgrade path.

### Documentation

- Added "Upgrading" and "Replicating to another machine" sections to the
  README, and a note on installing a tagged release via
  `pip install git+<url>@vX.Y.Z`.

## [0.1.0] - 2026-07-20

### Added

- Unix-socket HTTP daemon (`keyholderd`) authenticating callers via
  `SO_PEERCRED` and authorizing requests against a YAML policy.
- `keyholder` CLI (`grants`, `issue`, `run`, `revoke`) speaking the same
  protocol over the Unix socket.
- Providers: `github_app` (GitHub App installation tokens, tested
  end-to-end), `aws_sts` (AWS STS session credentials), `local_proxy`
  (opaque capability tokens, consumer pending), and `fake` (test-only).
- SQLite-backed lease store and JSONL audit log with hard-blocking of
  secret-like field names at write time.
- Bitwarden Secrets Manager integration (`bws` CLI) for resolving
  long-lived provider material.
- systemd service unit with `LoadCredentialEncrypted=` and hardening
  (`ProtectSystem=strict`, `NoNewPrivileges`, `RestrictAddressFamilies`, …).
- End-to-end deployment fixes enabling the daemon to run as a real
  systemd service on a live host.
