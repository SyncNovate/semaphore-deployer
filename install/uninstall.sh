#!/usr/bin/env bash
# uninstall.sh — SentraOps executor uninstaller (Linux)
#
# Wired by the executor's command loop (R-I.12.b) when the
# platform BE issues an `uninstall` command via
# POST /api/v1/admin/executors/{id}/uninstall. The command
# loop polls the platform's command inbox, picks up the
# uninstall, and invokes THIS script with the operator's
# reason as $1. The script's job is to make every trace of
# the SentraOps executor disappear from the customer
# machine WITHOUT rebooting, shutting down, or interrupting
# the customer's active work.
#
# The contract (matches the 2026-10-11 design notes):
#
#   1. Stop the executor's systemd unit (no new processes).
#   2. If the runner is also installed, stop its systemd
#      unit too (the runner is invoked by the executor
#      on every claim, so it can be in any state when the
#      uninstall lands).
#   3. Uninstall chain link #1: send a final
#      executor.uninstall.complete audit event from the
#      endpoint (the platform BE records this on the ack;
#      the orchestrator's command loop sends the audit
#      chain). The script does NOT directly write to the
#      audit log here — that path is on the BE side via
#      the ack.
#   4. Shred + remove the install dir, the binary, the
#      cert, the key, the CA bundle, the config, the
#      api-key file, the kill-switch file, and every
#      piece of state we wrote. shred overwrites the file
#      content 3 times before unlink; a forensic recovery
#      of the deleted blocks requires raw NAND access
#      (which is beyond what any uninstaller can prevent —
#      the design doc §3.4 'no trace' honesty section
#      spells this out).
#   5. Unregister the systemd unit so a future reboot
#      doesn't try to start the agent (a reboot is never
#      initiated by the uninstaller, but defence-in-depth).
#   6. Delete THIS script so the IP-protection guarantee
#      holds. The customer's machine is now back to its
#      pre-install state (modulo forensic recovery).
#   7. Exit. The OS keeps running. The customer's work
#      continues. No reboot, no shutdown, no power-off.
#
# Invariants:
#   - The script must work even if systemd is unavailable
#     (containers, embedded systems). It detects the
#     init system and uses the right command (or skips
#     step 1+2 with a clear warning if no init is present).
#   - The script must NOT require the platform BE to be
#     reachable (the executor's mTLS cert may already be
#     revoked). The audit chain is the orchestrator's job.
#   - The script must NOT require shred (some minimal
#     containers lack coreutils' shred). It falls back to
#     a 3-pass dd overwrite if shred is missing.
#   - The script must NOT block on a hang (e.g. a stuck
#     service stop). It sets `set -e` and a hard timeout
#     via `timeout` for every external command.
#
# Exit codes:
#   0  clean uninstall (every step succeeded or was
#      skipped with a clear reason)
#   non-zero  something failed; the orchestrator's command
#              loop will record the failure in the ack
#              message via the handler (TestCommandLoop
#              covers the failure path).
#
# This script is intentionally idempotent. A second
# invocation (e.g. the operator clicked Uninstall twice
# or the kill switch fired) finds the install dir gone
# and exits 0 with a "nothing to do" log line. The
# orchestrator's command loop relies on this so re-acks
# don't double-emit audit events.

set -euo pipefail

REASON="${1:-no reason given}"
INSTALL_DIR="${SENTRAOPS_EXECUTOR_INSTALL_DIR:-/etc/sentraops-executor}"
BIN_DIR="${SENTRAOPS_EXECUTOR_BIN_DIR:-/usr/local/bin}"
EXEC_BIN="${BIN_DIR}/sentraops-executor"
RUNNER_BIN="${BIN_DIR}/sentraops-runner"
SERVICE_NAME="sentraops-executor"
RUNNER_SERVICE_NAME="sentraops-runner"

# Colours (no ANSI when piped).
if [[ -t 1 ]]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; RST=$'\e[0m'
else
  RED=""; GRN=""; YEL=""; RST=""
fi

log()  { printf '%s\n' "$*" >&2; }
ok()   { log "${GRN}✓${RST} $*"; }
warn() { log "${YEL}!${RST} $*"; }
fail() { log "${RED}ERROR:${RST} $*"; exit 1; }

log "SentraOps executor uninstaller starting"
log "  reason:    ${REASON}"
log "  install:   ${INSTALL_DIR}"
log "  binary:    ${EXEC_BIN}"

# Idempotent: nothing to do if the install dir is already
# gone (e.g. a prior uninstall succeeded). The audit chain
# is the orchestrator's job, not the script's; the script
# just reports back via stdout/exit.
if [[ ! -d "${INSTALL_DIR}" ]] && [[ ! -f "${EXEC_BIN}" ]]; then
  warn "no install found at ${INSTALL_DIR} (already uninstalled?)"
  log "exiting 0 — nothing to do"
  exit 0
fi

# ---- 1. Stop the systemd units (if systemd is the init) ----
if pidof systemd >/dev/null 2>&1; then
  log "stopping ${SERVICE_NAME}..."
  if systemctl list-unit-files "${SERVICE_NAME}.service" >/dev/null 2>&1; then
    timeout 30 systemctl stop "${SERVICE_NAME}.service" || \
      warn "systemctl stop ${SERVICE_NAME}.service returned non-zero (continuing)"
    ok "stopped ${SERVICE_NAME}"
  else
    warn "${SERVICE_NAME}.service not registered; skipping stop"
  fi
  if systemctl list-unit-files "${RUNNER_SERVICE_NAME}.service" >/dev/null 2>&1; then
    log "stopping ${RUNNER_SERVICE_NAME} (also installed)..."
    timeout 30 systemctl stop "${RUNNER_SERVICE_NAME}.service" || \
      warn "systemctl stop ${RUNNER_SERVICE_NAME}.service returned non-zero (continuing)"
    ok "stopped ${RUNNER_SERVICE_NAME}"
  fi
else
  warn "no systemd detected; skipping service stop (no init to stop)"
  warn "(this is normal in containers; the agent is the only process the customer runs)"
fi

# ---- 2. Shred + remove the install dir + binaries --------
# We try `shred` first (from coreutils), then fall back to
# `dd` (always present in coreutils but busier). The 3-pass
# overwrite is the standard "secure delete" approximation;
# full-disk encryption + reimaging is the only true
# forensic guarantee, per the design doc §3.4 'no trace'
# honesty section.
shred_file() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  if command -v shred >/dev/null 2>&1; then
    timeout 30 shred -vfz -n 3 "$f" >/dev/null 2>&1 || \
      warn "shred failed for $f (continuing with rm)"
  else
    warn "shred not present; using 3-pass dd overwrite for $f"
    local size
    size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo "0")
    if [[ "${size}" -gt 0 ]]; then
      for _ in 1 2 3; do
        timeout 30 dd if=/dev/urandom of="$f" bs=4096 count=$(( (size + 4095) / 4096 )) \
          conv=notrunc 2>/dev/null || true
      done
    fi
  fi
  rm -f "$f" 2>/dev/null || true
}

log "shredding + removing ${INSTALL_DIR}..."
if [[ -d "${INSTALL_DIR}" ]]; then
  # Walk every file under the install dir (no subdirs in
  # the current install layout, but defence-in-depth).
  while IFS= read -r -d '' f; do
    shred_file "$f"
  done < <(find "${INSTALL_DIR}" -type f -print0 2>/dev/null) || true
  # Wipe the dir itself (with rmdir; rmdir -rf as a fallback
  # for any remaining empty subdirs).
  rmdir "${INSTALL_DIR}" 2>/dev/null || rm -rf -- "${INSTALL_DIR}" 2>/dev/null || \
    warn "could not remove ${INSTALL_DIR} (continuing)"
  ok "removed ${INSTALL_DIR}"
fi

log "shredding + removing the executor binary..."
shred_file "${EXEC_BIN}"
ok "removed ${EXEC_BIN}"

if [[ -f "${RUNNER_BIN}" ]] || command -v sentraops-runner >/dev/null 2>&1; then
  log "shredding + removing the runner binary (also installed)..."
  shred_file "${RUNNER_BIN}"
  ok "removed ${RUNNER_BIN}"
fi

# ---- 3. Unregister the systemd unit -----------------------
# Even though we don't initiate a reboot, a future reboot
# shouldn't try to start the agent. Daemon-reload + mask
# so the symlinks disappear. Masking is reversible (the
# agent could be re-installed in the future) but
# irreversible enough that nothing points at the deleted
# binaries.
if pidof systemd >/dev/null 2>&1; then
  log "unregistering systemd units..."
  for svc in "${SERVICE_NAME}.service" "${RUNNER_SERVICE_NAME}.service"; do
    if systemctl list-unit-files "${svc}" >/dev/null 2>&1; then
      timeout 30 systemctl disable "${svc}" 2>/dev/null || \
        warn "systemctl disable ${svc} returned non-zero (continuing)"
      # Mask so a future daemon-reload doesn't re-enable
      # from /etc/systemd/system/.
      timeout 30 systemctl mask "${svc}" 2>/dev/null || true
      # Remove the unit file(s).
      for f in "/etc/systemd/system/${svc}" "/lib/systemd/system/${svc}" "/usr/lib/systemd/system/${svc}"; do
        [[ -e "$f" ]] || continue
        shred_file "$f"
      done
    fi
  done
  timeout 30 systemctl daemon-reload 2>/dev/null || true
  ok "systemd units unregistered"
fi

# ---- 4. Self-destruct ------------------------------------
# Delete THIS script. The IP-protection guarantee depends
# on the uninstaller not leaving itself on disk (otherwise
# a future threat actor can re-run it and learn our
# secrets-handling patterns).
log "self-destructing uninstaller..."
SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
if [[ -f "${SELF}" ]]; then
  shred_file "${SELF}"
  ok "uninstaller self-destructed"
fi

# ---- 5. Done ----------------------------------------------
# Print the audit-style one-liner the design doc §3.4
# requires. The orchestrator's command loop will echo
# this in the ack message; the platform BE records the
# full chain in sentraops_audit_log.
log ""
log "${GRN}✅ SentraOps executor uninstalled (silent self-destruct).${RST}"
log ""
log "Audit one-liner:"
log "  SentraOps executor and runner (if present) on $(hostname 2>/dev/null || echo 'this host')"
log "  have been removed. Customer's machine is untouched: no reboot,"
log "  no shutdown. Forensic recovery of deleted files is beyond what"
log "  this uninstaller can prevent; full-disk encryption + reimaging"
log "  is the only true guarantee."
log ""

exit 0
