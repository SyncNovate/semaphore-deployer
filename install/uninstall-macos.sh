#!/usr/bin/env bash
# uninstall-macos.sh — SentraOps executor uninstaller (macOS)
#
# Wired by the executor's command loop (R-I.12.b) when the
# platform BE issues an `uninstall` command. Same contract
# as install/uninstall.sh (Linux) — see that file's header
# for the full design rationale. This file is the macOS
# counterpart: launchd instead of systemd, /Library/LaunchDaemons
# instead of /etc/systemd/system/, /usr/local/bin for the
# binary (same as Linux), /etc/sentraops-executor for the
# config (same as Linux; the install script writes the
# config dir to be portable across the two POSIX systems).
#
# macOS-specific bits:
#
#   - launchctl bootout / launchctl unload: stops the
#     service (analogue of systemctl stop).
#   - launchctl disable <service>: marks the plist as
#     disabled so launchd doesn't reload it on the next
#     user login / system boot (defence-in-depth — we
#     don't initiate a reboot).
#   - The plist is at /Library/LaunchDaemons/com.sentraops
#     .executor.plist (the install script picks that
#     location for system-level services).
#   - macOS `srm` (secure-remove) is preferred over
#     shred if present; both fall back to dd overwrite.
#
# The contract is identical to the Linux uninstaller:
#   - No reboot, no shutdown.
#   - Silent self-destruct.
#   - Audit chain on the BE side via the orchestrator's
#     command loop ack; the script does NOT directly
#     write to the platform audit log.
#   - Idempotent: a second invocation exits 0 cleanly.

set -euo pipefail

REASON="${1:-no reason given}"
INSTALL_DIR="${SENTRAOPS_EXECUTOR_INSTALL_DIR:-/etc/sentraops-executor}"
BIN_DIR="${SENTRAOPS_EXECUTOR_BIN_DIR:-/usr/local/bin}"
EXEC_BIN="${BIN_DIR}/sentraops-executor"
RUNNER_BIN="${BIN_DIR}/sentraops-runner"
PLIST_PATH="/Library/LaunchDaemons/com.sentraops.executor.plist"
RUNNER_PLIST_PATH="/Library/LaunchDaemons/com.sentraops.runner.plist"
LAUNCHD_LABEL="com.sentraops.executor"
RUNNER_LAUNCHD_LABEL="com.sentraops.runner"

if [[ -t 1 ]]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; RST=$'\e[0m'
else
  RED=""; GRN=""; YEL=""; RST=""
fi

log()  { printf '%s\n' "$*" >&2; }
ok()   { log "${GRN}✓${RST} $*"; }
warn() { log "${YEL}!${RST} $*"; }

log "SentraOps executor uninstaller (macOS) starting"
log "  reason:    ${REASON}"
log "  install:   ${INSTALL_DIR}"
log "  binary:    ${EXEC_BIN}"

# Idempotent: nothing to do if the install dir is already
# gone.
if [[ ! -d "${INSTALL_DIR}" ]] && [[ ! -f "${EXEC_BIN}" ]]; then
  warn "no install found at ${INSTALL_DIR} (already uninstalled?)"
  log "exiting 0 — nothing to do"
  exit 0
fi

# ---- 1. Stop the launchd jobs (if launchd is the init) ----
# macOS always has launchd, but a chroot or a custom init
# might not. We check `which launchctl` so the script
# fails clean in a non-macOS environment.
if command -v launchctl >/dev/null 2>&1; then
  log "stopping ${LAUNCHD_LABEL} via launchctl bootout..."
  # bootout is the modern API; unload is the legacy one
  # that still works for service targets. Try both.
  timeout 30 launchctl bootout "system/${LAUNCHD_LABEL}" 2>/dev/null || \
    timeout 30 launchctl unload -w "${PLIST_PATH}" 2>/dev/null || \
    warn "launchctl stop for ${LAUNCHD_LABEL} returned non-zero (continuing — may already be stopped)"
  ok "stopped ${LAUNCHD_LABEL}"

  if [[ -f "${RUNNER_PLIST_PATH}" ]]; then
    log "stopping ${RUNNER_LAUNCHD_LABEL} (also installed)..."
    timeout 30 launchctl bootout "system/${RUNNER_LAUNCHD_LABEL}" 2>/dev/null || \
      timeout 30 launchctl unload -w "${RUNNER_PLIST_PATH}" 2>/dev/null || \
      warn "launchctl stop for ${RUNNER_LAUNCHD_LABEL} returned non-zero (continuing)"
    ok "stopped ${RUNNER_LAUNCHD_LABEL}"
  fi
else
  warn "no launchctl detected; skipping service stop (non-macOS or chroot)"
fi

# ---- 2. Disable the launchd jobs (defence-in-depth) ------
# We don't initiate a reboot, but a future user login or
# a system restart shouldn't try to start the agent.
# `launchctl disable` writes a disabled-state override into
# /var/db/com.apple.xpc.launchd/disabled.plist.
if command -v launchctl >/dev/null 2>&1; then
  log "disabling launchd jobs..."
  for lbl in "${LAUNCHD_LABEL}" "${RUNNER_LAUNCHD_LABEL}"; do
    timeout 30 launchctl disable "system/${lbl}" 2>/dev/null || \
      warn "launchctl disable ${lbl} returned non-zero (continuing)"
  done
  ok "launchd jobs disabled"
fi

# ---- 3. Shred + remove the install dir + binaries --------
# macOS-specific: prefer `srm` (secure remove) if present,
# fall back to shred (from coreutils via brew or similar),
# then to dd. The 3-pass overwrite is the same standard
# "secure delete" approximation as the Linux uninstaller.
shred_file() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  if command -v srm >/dev/null 2>&1; then
    timeout 60 srm -vz "$f" 2>/dev/null || \
      warn "srm failed for $f (continuing with rm)"
  elif command -v shred >/dev/null 2>&1; then
    timeout 30 shred -vfz -n 3 "$f" >/dev/null 2>&1 || \
      warn "shred failed for $f (continuing with rm)"
  else
    warn "neither srm nor shred present; using 3-pass dd overwrite for $f"
    local size
    size=$(stat -f%z "$f" 2>/dev/null || echo "0")
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
  while IFS= read -r -d '' f; do
    shred_file "$f"
  done < <(find "${INSTALL_DIR}" -type f -print0 2>/dev/null) || true
  rmdir "${INSTALL_DIR}" 2>/dev/null || rm -rf -- "${INSTALL_DIR}" 2>/dev/null || \
    warn "could not remove ${INSTALL_DIR} (continuing)"
  ok "removed ${INSTALL_DIR}"
fi

log "shredding + removing the executor binary..."
shred_file "${EXEC_BIN}"
ok "removed ${EXEC_BIN}"

if [[ -f "${RUNNER_BIN}" ]]; then
  log "shredding + removing the runner binary (also installed)..."
  shred_file "${RUNNER_BIN}"
  ok "removed ${RUNNER_BIN}"
fi

# ---- 4. Unregister the launchd plist ----------------------
# Remove the plist files from /Library/LaunchDaemons so
# launchd doesn't re-discover them on a future boot.
log "removing launchd plists..."
for plist in "${PLIST_PATH}" "${RUNNER_PLIST_PATH}"; do
  if [[ -f "${plist}" ]]; then
    shred_file "${plist}"
  fi
done
ok "launchd plists removed"

# ---- 5. Self-destruct ------------------------------------
log "self-destructing uninstaller..."
SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
if [[ -f "${SELF}" ]]; then
  shred_file "${SELF}"
  ok "uninstaller self-destructed"
fi

# ---- 6. Done ----------------------------------------------
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
