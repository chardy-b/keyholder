#!/usr/bin/env bash
# Idempotent installer for keyholderd. Safe to re-run after `git pull` as the
# upgrade path: reinstalls the package, restarts the service, never clobbers
# an existing policy or BWS credential.
#
# Usage: sudo packaging/install.sh [--client-user USER] [--bws-token-file PATH] [--no-start]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CLIENT_USER=""
BWS_TOKEN_FILE=""
NO_START=0

log() { printf '[install] %s\n' "$*"; }
die() { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  echo "Usage: sudo $0 [--client-user USER] [--bws-token-file PATH] [--no-start]"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --client-user)
      CLIENT_USER="${2:-}"; [ -n "$CLIENT_USER" ] || die "--client-user requires a value"; shift 2 ;;
    --bws-token-file)
      BWS_TOKEN_FILE="${2:-}"; [ -n "$BWS_TOKEN_FILE" ] || die "--bws-token-file requires a value"; shift 2 ;;
    --no-start)
      NO_START=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      die "unknown argument: $1" ;;
  esac
done

# --- 1. Preflight ------------------------------------------------------
preflight() {
  [ "$(id -u)" -eq 0 ] || die "must be run as root (try: sudo $0)"

  command -v systemctl >/dev/null 2>&1 || die "systemctl not found; keyholder requires systemd"
  local sysd_ver
  sysd_ver="$(systemctl --version | head -1 | awk '{print $2}')"
  [ "${sysd_ver:-0}" -ge 254 ] 2>/dev/null || die "systemd >= 254 required, found $sysd_ver"

  command -v python3 >/dev/null 2>&1 || die "python3 not found"
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
    || die "python3 >= 3.11 required, found $(python3 --version 2>&1)"

  command -v bws >/dev/null 2>&1 || die "bws (Bitwarden Secrets Manager CLI) not found on PATH"

  log "preflight ok: systemd $sysd_ver, $(python3 --version 2>&1), bws found, repo root $REPO_ROOT"
}

# --- 2. Users/groups -----------------------------------------------------
install_sysusers() {
  install -m 0644 "$REPO_ROOT/packaging/keyholder.sysusers.conf" /etc/sysusers.d/keyholder.conf
  systemd-sysusers /etc/sysusers.d/keyholder.conf
  log "sysusers applied: keyholder user, keyholder-clients group"

  if [ -n "$CLIENT_USER" ]; then
    if id -nG "$CLIENT_USER" 2>/dev/null | tr ' ' '\n' | grep -qx keyholder-clients; then
      log "user $CLIENT_USER already in keyholder-clients, skipped"
    else
      usermod -aG keyholder-clients "$CLIENT_USER"
      log "added $CLIENT_USER to keyholder-clients"
    fi
    log "NOTE: group membership only takes effect in new shells. Run 'newgrp keyholder-clients' or re-login as $CLIENT_USER."
  fi
}

# --- 3. Config dir ---------------------------------------------------------
install_config_dir() {
  install -d -o root -g keyholder -m 0750 /etc/keyholder
  log "config dir /etc/keyholder ready"
}

# --- 4. BWS credential -----------------------------------------------------
install_bws_credential() {
  local cred=/etc/keyholder/bws-access-token.cred
  if [ -e "$cred" ]; then
    log "BWS credential already present at $cred, leaving alone"
    return
  fi

  if [ -n "$BWS_TOKEN_FILE" ]; then
    [ -r "$BWS_TOKEN_FILE" ] || die "--bws-token-file $BWS_TOKEN_FILE is not readable"
    systemd-creds encrypt --name=bws-access-token "$BWS_TOKEN_FILE" "$cred"
  else
    local token
    read -rs -p "Enter the Bitwarden Secrets Manager access token: " token
    echo
    [ -n "$token" ] || die "no token entered"
    printf '%s' "$token" | systemd-creds encrypt --name=bws-access-token - "$cred"
    unset token
  fi

  chown root:keyholder "$cred"
  chmod 0640 "$cred"
  log "BWS credential encrypted to $cred"
  log "NOTE: this file is sealed to this host's key/TPM and cannot be copied between machines — every host must run this step itself."
}

# --- 5. Venv install ---------------------------------------------------
install_venv() {
  local venv=/opt/keyholder/venv
  local fresh=0
  if [ ! -x "$venv/bin/python3" ]; then
    python3 -m venv "$venv"
    fresh=1
    log "created venv at $venv"
  else
    log "venv at $venv already exists"
  fi

  "$venv/bin/pip" install --upgrade pip >/dev/null
  if [ "$fresh" -eq 1 ]; then
    "$venv/bin/pip" install "$REPO_ROOT"
    log "installed keyholder (with dependencies) into fresh venv"
  else
    "$venv/bin/pip" install --force-reinstall --no-deps "$REPO_ROOT"
    log "reinstalled keyholder into existing venv"
  fi

  install -m 0755 "$venv/bin/keyholder"  /usr/local/bin/keyholder
  install -m 0755 "$venv/bin/keyholderd" /usr/local/bin/keyholderd
  log "entry points installed to /usr/local/bin/keyholder{,d}"
}

# --- 6. Unit + policy -------------------------------------------------------
FRESH_POLICY=0

install_unit_and_policy() {
  install -m 0644 "$REPO_ROOT/packaging/keyholder.service" /etc/systemd/system/keyholder.service
  log "service unit installed"

  local policy=/etc/keyholder/policy.yaml
  if [ -e "$policy" ]; then
    log "policy already present at $policy, leaving alone"
  else
    install -m 0640 -o root -g keyholder "$REPO_ROOT/packaging/policy.example.yaml" "$policy"
    FRESH_POLICY=1
    log "installed example policy to $policy (edit before use)"
  fi

  systemctl daemon-reload
  log "systemd units reloaded"
}

# --- 7. Start ---------------------------------------------------------
start_service() {
  if [ "$NO_START" -eq 1 ]; then
    log "--no-start given, skipping service start"
    return
  fi

  if systemctl is-active --quiet keyholder.service; then
    systemctl restart keyholder.service
    log "keyholder.service restarted"
  else
    systemctl enable --now keyholder.service
    log "keyholder.service enabled and started"
  fi

  if [ "$FRESH_POLICY" -eq 1 ]; then
    log "REMINDER: /etc/keyholder/policy.yaml is the stock example. Edit it for your callers/grants, then 'systemctl restart keyholder.service' before expecting 'keyholder grants' to return anything."
  fi

  log "running keyholder doctor:"
  /usr/local/bin/keyholder doctor || true
}

main() {
  preflight
  install_sysusers
  install_config_dir
  install_bws_credential
  install_venv
  install_unit_and_policy
  start_service
  log "done"
}

main "$@"
