#!/usr/bin/env bash
# Syntax-check the SentraOps deployment playbooks.
#
# Why a shell script instead of just `ansible-playbook --syntax-check`:
# we want CI to fail loudly + early when the playbook has a typo or
# references an unknown module. Running on the executor's workstation
# (`mavis-access@…`) keeps the test surface small — no actual Windows
# target needed.
#
# Usage:
#   ansible/tests/syntax-check.sh
#
# Exits non-zero on any failure. Designed to be run from CI as
#   ./ansible/tests/syntax-check.sh || exit 1
set -euo pipefail

PLAYBOOK_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INVENTORY="${PLAYBOOK_DIR}/inventory/sample/windows-hosts.yml"

if ! command -v ansible-playbook >/dev/null 2>&1; then
  echo "FATAL: ansible-playbook not on PATH" >&2
  echo "Install: pip install ansible ansible.windows community.windows" >&2
  exit 2
fi

echo "==> syntax-checking windows-install-runner.yml"
ansible-playbook \
  --syntax-check \
  -i "${INVENTORY}" \
  "${PLAYBOOK_DIR}/windows-install-runner.yml"

echo "==> syntax-check PASS"
