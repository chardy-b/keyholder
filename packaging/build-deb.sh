#!/usr/bin/env bash
# Build a keyholder .deb via nfpm. Bundles the project wheel plus every
# dependency wheel so the postinst script needs no network access.
#
# Usage: packaging/build-deb.sh [output-dir]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/dist}"

log() { printf '[build-deb] %s\n' "$*"; }
die() { printf '[build-deb] ERROR: %s\n' "$*" >&2; exit 1; }

command -v nfpm >/dev/null 2>&1 || die "nfpm not found on PATH. Install it: https://nfpm.goreleaser.com/install/"
command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"

KEYHOLDER_VERSION="$(python3 -c '
import tomllib
with open("'"$REPO_ROOT"'/pyproject.toml", "rb") as fh:
    print(tomllib.load(fh)["project"]["version"])
')"
[ -n "$KEYHOLDER_VERSION" ] || die "could not determine version from pyproject.toml"
export KEYHOLDER_VERSION
log "building keyholder $KEYHOLDER_VERSION"

STAGE_DIR="$SCRIPT_DIR/staging"
WHEEL_DIR="$STAGE_DIR/wheels"
rm -rf "$STAGE_DIR"
mkdir -p "$WHEEL_DIR"

log "building wheels (project + dependencies) into $WHEEL_DIR"
python3 -m pip wheel "$REPO_ROOT" -w "$WHEEL_DIR"

mkdir -p "$OUT_DIR"
log "packaging with nfpm -> $OUT_DIR"
# nfpm resolves each content's relative `src:` against the current working
# directory, not the config file's location -- cd into packaging/ so
# ./keyholder.service, ./staging/wheels, etc. resolve correctly.
(cd "$SCRIPT_DIR" && nfpm package -f nfpm.yaml -p deb -t "$OUT_DIR")

DEB_FILE="$(find "$OUT_DIR" -maxdepth 1 -name '*.deb' -newer "$SCRIPT_DIR/nfpm.yaml" -print -quit)"
log "done: ${DEB_FILE:-see $OUT_DIR}"
