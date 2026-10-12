#!/usr/bin/env bash
# runner_uninstall.sh — SentraOps runner-only self-destruct (Linux)
#
# R-F.3.b: the platform-specific uninstaller for the
# runner-only binary. Invoked by runner/command_loop.go's
# `handleUninstall` when the SOC operator issues a remote
# uninstall (or the local kill switch fires).
#
# Contract (R-I.12 design — locked in by the user's
# 2026-10-11 annotations):
#
#   1. Stop the runner's systemd service so no new
#      processes are started.
#   2. Shred + remove the install dir
#      (/etc/sentraops-runner/) and the binary
#      (/usr/local/bin/sentraops-runner).
#   3. Unregister the systemd unit so the OS doesn't try
#      to start the agent on the next boot.
#   4. Send the executor.uninstall.complete audit event
#      (the platform BE records this from the ack the
#      runner's command loop posts after we exit).
#   5. Delete the uninstaller script itself so the IP
#      protection guarantee holds (Wazuh's posture).
#   6. Exit. NO REBOOT, NO SHUTDOWN. The agent goes silent
#      but the customer's machine keeps running.
#
# Idempotent: safe to run twice. A second invocation finds
# the install dir already gone and exits 0.
#
# Exit codes:
#   0  success (or already uninstalled)
#   1  internal error (shred failed, etc.)
#
# Arguments:
#   $1  reason  (optional)  the SOC operator's reason from
#                            the uninstall modal. The runner
#                            has already recorded it in the
#                            platform BE inbox payload; we
#                            just echo it into the final log
#                            line for the customer's
#                            post-mortem.

set -euo pipefail

REASON="${1:-no reason given}"

INSTALL_DIR="/etc/sentraops-runner"
BIN_PATH="/usr/local/bin/sentraops-runner"
SERVICE_FILE="/etc/systemd/system/sentraops-runner.service"

# Best-effort logging. Stdout / stderr may be captured by
# the runner's command loop or by the SIEM. We do NOT depend
# on a logger being available.
log() { printf '%s\n' "[runner_uninstall] $*" >&2; }

log "received uninstall command — reason: ${REASON}"

# ---- 1. Stop the systemd service --------------------------------
if systemctl list-unit-files "sentraops-runner.service" 2>/dev/null | grep -q "sentraops-runner.service"; then
  log "stopping sentraops-runner.service"
  systemctl stop sentraops-runner.service 2>/dev/null || log "service stop returned non-zero (continuing)"
  systemctl disable sentraops-runner.service 2>/dev/null || log "service disable returned non-zero (continuing)"
else
  log "sentraops-runner.service not installed (already uninstalled?)"
fi

# ---- 2. Shred + remove the install dir + binary -----------------
# shred is a best-effort. On a filesystem without shred
# (e.g. busybox) we fall back to a plain overwrite + rm.
shred_file() {
  local f="$1"
  if [[ ! -e "${f}" ]]; then return 0; fi
  if command -v shred >/dev/null 2>&1; then
    shred -u -z -n 1 "${f}" 2>/dev/null || rm -f "${f}"
  else
    dd if=/dev/urandom of="${f}" bs=4096 count=$(($(stat -c '%s' "${f}") / 4096 + 1)) 2>/dev/null || true
    rm -f "${f}"
  fi
}

if [[ -d "${INSTALL_DIR}" ]]; then
  log "shredding contents of ${INSTALL_DIR}"
  # Cert + key + API key + kill switch — shred each in
  # place. We then rm the directory itself.
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

# ---- 3. Remove the binary -----------------------------------------
if [[ -f "${BIN_PATH}" ]]; then
  log "shredding ${BIN_PATH}"
  shred_file "${BIN_PATH}"
else
  log "${BIN_PATH} not present (already removed?)"
fi

# ---- 4. Remove the systemd unit -----------------------------------
if [[ -f "${SERVICE_FILE}" ]]; then
  rm -f "${SERVICE_FILE}"
  log "removed ${SERVICE_FILE}"
fi
systemctl daemon-reload 2>/dev/null || true

# ---- 5. Self-delete the uninstaller -------------------------------
# The runner's command loop will not call us twice (the
# platform BE 404s the command on the next tick), but a
# copy of the uninstaller on disk is unnecessary and is
# itself an information leak (it shows the customer's
# IT admin what the install layout was).
SCRIPT_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
if [[ -f "${SCRIPT_SELF}" ]]; then
  rm -f "${SCRIPT_SELF}"
  log "self-deleted ${SCRIPT_SELF}"
fi

# ---- 6. Final log line -------------------------------------------
log "uninstall complete — agent silent, customer machine still running, no reboot"
exit 0
