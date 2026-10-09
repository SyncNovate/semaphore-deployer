# SentraOps deployment playbooks

Ansible playbooks the customer-side deployment executor (`executor/`) invokes to install the **SentraOps runner** on target endpoints. The executor (`semaphore-deployer/executor/`) is a different binary — it lives on the customer's deployment server and orchestrates the install; the runner is the agent installed on the target endpoint.

| File | Purpose |
|---|---|
| `windows-install-runner.yml` | Windows install (PSRP/Kerberos for AD-joined, cert-WinRM for workgroup) |
| `inventory/sample/windows-hosts.yml` | Sample inventory |
| `inventory/sample/group_vars/all.yml` | Default group vars (network defaults only) |
| `tests/syntax-check.sh` | `ansible-playbook --syntax-check` for CI |

## Windows transport choice

The playbook refuses to run unless every target has `winrm_transport: kerberos` OR `winrm_transport: cert` set in its inventory vars. The default transport map:

| AD-joined | Workgroup | Transport |
|---|---|---|
| ✓ | — | `psrp` + `kerberos` (Negotiate picks Kerberos over HTTPS) |
| — | ✓ | `winrm` + `cert` (client cert, server cert validated) |
| ✓ | ✓ | operator picks per host |

**NEVER** use unvalidated WinRM HTTP/5985 in production. The playbook's `assert` task guards against this — see `windows-install-runner.yml` for the fail-closed check.

## Running

The executor's `Run()` invokes:

```bash
ansible-playbook <executor.FS>/ansible/windows-install-runner.yml \
  -i <per-campaign-inventory> \
  --extra-vars "@<per-campaign-vars>"
```

…with the following env vars set from the executor's `JobEnv`:

| Env | Source |
|---|---|
| `SENTRAOPS_RUNNER_PACKAGE_URL` | campaign `package_version` + R-E.1 TUF root |
| `SENTRAOPS_RUNNER_PACKAGE_SHA256` | TUF-pinned SHA256 of the package |
| `SENTRAOPS_RUNNER_VERSION` | campaign `package_version` |
| `SENTRAOPS_RUNNER_SERVER_URL` | executor's `Config.ServerURL` |
| `SENTRAOPS_RUNNER_SERVER_CA_FILE` | executor's `Config.ServerCAFile` |
| `SENTRAOPS_RUNNER_TENANT_ID` | executor's `Config.TenantID` |
| `SENTRAOPS_RUNNER_DEPLOYMENT_ZONE_ID` | executor's `Config.DeploymentZoneID` |

The executor's `Run()` validates `job.Playbook.SHA256` against the on-disk playbook file before invoking `ansible-playbook` — so a MITM swapping the playbook file mid-flight is caught.

## Idempotency

Re-running the playbook on an already-installed target is a no-op:

- The version-check task (`existing_install_check` + `install_required` fact) skips all subsequent tasks when the installed version matches.
- The scheduled task creation is idempotent (`win_scheduled_task` is a no-op if the task already exists with the same action).
- The config-file write is conditional on `install_required` only.

## Tests

Run from the repo root:

```bash
./ansible/tests/syntax-check.sh
```

That's the entire test surface in R-I.5 — there are no actual Windows targets in the executor's environment to run an integration test against. Real install/upgrade verification happens during the R-I.11 live QA cycle (once the executor binary is wired into a live fork-env).

## Linux transport

`linux-install-runner.yml` runs over SSH with **strict host-key pinning** (`StrictHostKeyChecking=yes`, pinned via `/etc/ssh/ssh_known_hosts`). Private key + user are resolved via the executor's `SecretStore` (R-I.10 backends); sudo with `NOPASSWD` is preferred for the automation user.

| Pattern | Used for |
|---|---|
| `connection: ssh` + key-based auth | normal deploy (preferred) |
| `connection: ssh` + `--ask-pass` | legacy fallback (interactive; CI/CD unfriendly) |

The playbook fails closed if the env vars on §"Running" are missing — see the `assert` task.

---

## R-I.7 follows the same shape for macOS

R-I.7 is DEFERRED per the plan doc — macOS runner support needs (a) Apple Developer ID for code-signing + notarization and (b) a macOS VM in the CI lane. When those unblock, a `macos-install-runner.yml` follows the same shape.
