#!/usr/bin/env bash
# Syntax-check the SentraOps deployment playbooks.
#
# Checks BOTH the Windows + Linux installers (plus sample
# inventory parsing) on the executor's workstation.
# No actual Windows / Linux target is needed — `--syntax-check`
# just validates YAML + module refs.
#
# Usage:
#   ansible/tests/syntax-check.sh
#
# Exits non-zero on any failure. Designed to be run from CI as
#   ./ansible/tests/syntax-check.sh || exit 1
set -euo pipefail

PLAYBOOK_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v ansible-playbook >/dev/null 2>&1; then
  echo "FATAL: ansible-playbook not on PATH" >&2
  echo "Install: pip3 install --user ansible ansible-core" >&2
  echo "         ansible-galaxy collection install ansible.windows community.windows" >&2
  exit 2
fi

echo "==> syntax-checking windows-install-runner.yml"
ansible-playbook \
  --syntax-check \
  -i "${PLAYBOOK_DIR}/inventory/sample/windows-hosts.yml" \
  "${PLAYBOOK_DIR}/windows-install-runner.yml"

echo "==> syntax-checking linux-install-runner.yml"
ansible-playbook \
  --syntax-check \
  -i "${PLAYBOOK_DIR}/inventory/sample/linux-hosts.yml" \
  "${PLAYBOOK_DIR}/linux-install-runner.yml"

echo "==> syntax-check PASS"
