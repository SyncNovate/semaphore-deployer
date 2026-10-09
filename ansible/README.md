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

## R-I.6 follows the same shape

R-I.6 (Linux playbook) will land in `ansible/linux-install-runner.yml` with the same task structure (validate env / download / install / scheduled-task-equivalent / smoke-check) and a different transport layer (SSH with verified host keys; see plan doc §13.12).
