#!/usr/bin/env bash
# runner_uninstall-macos.sh — SentraOps runner-only self-destruct (macOS)
#
# R-F.3.b: the macOS uninstaller for the runner-only binary.
# Mirrors runner_uninstall.sh (Linux) — same contract, same
# idempotency, same silent self-destruct posture. The only
# platform-specific bits are the launchd plist and the
# binary path (/usr/local/bin/sentraops-runner).
#
# macOS uses launchd instead of systemd. The install script
# ships a `com.sentraops.runner.plist` to
# /Library/LaunchDaemons/. The plist unloads + removes
# itself.

set -euo pipefail

REASON="${1:-no reason given}"

INSTALL_DIR="/etc/sentraops-runner"
BIN_PATH="/usr/local/bin/sentraops-runner"
PLIST_PATH="/Library/LaunchDaemons/com.sentraops.runner.plist"

log() { printf '%s\n' "[runner_uninstall] $*" >&2; }

log "received uninstall command — reason: ${REASON}"

# ---- 1. Unload the launchd plist ---------------------------------
if [[ -f "${PLIST_PATH}" ]]; then
  log "unloading ${PLIST_PATH}"
  launchctl unload "${PLIST_PATH}" 2>/dev/null || log "launchctl unload returned non-zero (continuing)"
  rm -f "${PLIST_PATH}"
  log "removed ${PLIST_PATH}"
else
  log "${PLIST_PATH} not present (already uninstalled?)"
fi

# ---- 2. Stop the runner (best-effort) ---------------------------
# The plist is gone so launchd will not respawn it. Any
# running process is the one the operator issued the
# uninstall on; pkill -f catches it without us needing to
# know its exact name.
pkill -f "sentraops-runner" 2>/dev/null || true

# ---- 3. Shred + remove the install dir + binary -----------------
shred_file() {
  local f="$1"
  if [[ ! -e "${f}" ]]; then return 0; fi
  if command -v shred >/dev/null 2>&1; then
    shred -u -z -n 1 "${f}" 2>/dev/null || rm -f "${f}"
  else
    dd if=/dev/urandom of="${f}" bs=4096 count=$(($(stat -f '%z' "${f}") / 4096 + 1)) 2>/dev/null || true
    rm -f "${f}"
  fi
}

if [[ -d "${INSTALL_DIR}" ]]; then
  log "shredding contents of ${INSTALL_DIR}"
  for f in "${INSTALL_DIR}/cert.pem" \
           "${INSTALL_DIR}/key.pem" \
           "${INSTALL_DIR}/ca.pem" \
           "${INSTALL_DIR}/api_key" \
           "${INSTALL_DIR}/kill_switch" \
           "${INSTALL_DIR}/config.yaml" \
           "${INSTALL_DIR}/audit.log" \
           "${INSTALL_DIR}/runner.log"; do
    shred_file "${f}"
  done
  rm -rf "${INSTALL_DIR}"
  log "removed ${INSTALL_DIR}"
else
  log "${INSTALL_DIR} not present (already removed?)"
fi

if [[ -f "${BIN_PATH}" ]]; then
  log "shredding ${BIN_PATH}"
  shred_file "${BIN_PATH}"
else
  log "${BIN_PATH} not present (already removed?)"
fi

# ---- 4. Self-delete the uninstaller -------------------------------
SCRIPT_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
if [[ -f "${SCRIPT_SELF}" ]]; then
  rm -f "${SCRIPT_SELF}"
  log "self-deleted ${SCRIPT_SELF}"
fi

# ---- 5. Final log line -------------------------------------------
log "uninstall complete — agent silent, customer machine still running, no reboot"
exit 0
