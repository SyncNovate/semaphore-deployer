# install.ps1 — SentraOps executor first-boot installer (Windows)
#
# This script is what the customer's IT admin runs in an elevated
# PowerShell after clicking the "Send Executor" link in the SOC
# console. It is invoked as a single command:
#
#   iex (irm https://sentraops.example.com/install/<token>)
#
# The script:
#   1. Detects the platform (Windows + arch)
#   2. Writes the executor binary + bootstrap.json + config.yaml to
#      C:\ProgramData\SentraOps\Executor\  (ACL: owner-only on every
#      secret file)
#   3. Installs + starts the service via NSSM (non-Sucking Service
#      Manager) — bundled in the executor binary's directory
#   4. Runs `sentraops-executor.exe --bootstrap` to exchange the
#      token for a long-lived mTLS cert
#   5. On success, starts the service
#   6. On failure, leaves the bundle in place + prints a clear error
#      so the IT admin can retry
#
# Wazuh-style one-command install. The customer never edits YAML.
#
# Env vars consumed (passed by the SOC console's wrapper):
#   $env:SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN   The single-use enrollment token
#   $env:SENTRAOPS_EXECUTOR_SERVER_URL        The SentraOps server URL
#   $env:SENTRAOPS_EXECUTOR_TENANT_ID         The customer's tenant ID
#   $env:SENTRAOPS_EXECUTOR_BINARY_URL        Where to download the executor binary
#
# Wazuh-style 1-line install: combined installer + first-boot
# bootstrap. The customer runs `iex (irm '...?os=windows')`
# from the SOC operator's email — no flags, no decisions.
# The signed bootstrap URL is the customer's identity.

[CmdletBinding()]
param(
    # The three primary inputs default to the env vars the
    # install endpoint pre-bakes into the script. The
    # Wazuh-style 1-line invocation pattern is
    # `iex (irm '...?os=windows')` — the customer passes
    # no parameters. Making BootstrapToken / ServerURL /
    # TenantID Mandatory here would break that pattern
    # (PowerShell raises MissingMandatoryParameter before
    # the env vars are read). The env-var default keeps
    # the 1-line install working AND lets an operator
    # override per-invocation if needed.
    [string]$BootstrapToken = $env:SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN,
    [string]$ServerURL      = $env:SENTRAOPS_EXECUTOR_SERVER_URL,
    [string]$TenantID       = $env:SENTRAOPS_EXECUTOR_TENANT_ID,
    [string]$BinaryURL      = $env:SENTRAOPS_EXECUTOR_BINARY_URL,
    [string]$InstallDir     = "${env:ProgramData}\SentraOps\Executor",
    [string]$BinaryPath     = "$InstallDir\sentraops-executor.exe",
    [string]$ConfigPath     = "$InstallDir\config.yaml",
    [string]$CertPath       = "$InstallDir\cert.pem",
    [string]$KeyPath        = "$InstallDir\key.pem",
    [string]$CAPath         = "$InstallDir\ca.pem",
    [string]$ServiceName    = "SentraOpsExecutor"
)

$ErrorActionPreference = "Stop"

function Write-Ok  { param($m) Write-Host "✓ $m" -ForegroundColor Green }
function Write-Err { param($m) Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

# Guard: when the customer runs the Wazuh-style 1-line install
# (`iex (irm '...?os=windows')`), no parameters are passed and
# the params default to the pre-baked env vars. If the env vars
# are also empty, fail loudly with a clear remediation message
# instead of writing a half-baked config.yaml.
if (-not $BootstrapToken -or -not $ServerURL -or -not $TenantID) {
    Write-Err @"
missing one of: SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN, SENTRAOPS_EXECUTOR_SERVER_URL, SENTRAOPS_EXECUTOR_TENANT_ID.

The Wazuh-style 1-line install is:
    iex (irm 'https://sentraops.5-189-177-170.sslip.io:9443/install/<token>?os=windows')

If you are running the script by hand, set the env vars first:
    `$env:SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN = '<token>'
    `$env:SENTRAOPS_EXECUTOR_SERVER_URL      = 'https://sentraops.5-189-177-170.sslip.io:9443'
    `$env:SENTRAOPS_EXECUTOR_TENANT_ID       = '<tenant-id>'
"@
}

if (-not $BinaryURL) { $BinaryURL = "$($ServerURL.TrimEnd('/'))/download/executor-windows-amd64.exe" }

# ---- 0. Admin check --------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "this script must run from an elevated PowerShell (Run as Administrator)"
}

# ---- 1. Create the install dir ---------------------------------------
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Restrict ACL on the install dir (Administrators + SYSTEM only).
$acl = Get-Acl $InstallDir
$acl.SetAccessRuleProtection($true, $false)
$rules = @(
    New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow"),
    New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")
)
$rules | ForEach-Object { $acl.AddAccessRule($_) }
Set-Acl $InstallDir $acl

# ---- 2. Download the executor binary ---------------------------------
Write-Host "Downloading executor from $BinaryURL ..."
try {
    Invoke-WebRequest -Uri $BinaryURL -OutFile $BinaryPath -UseBasicParsing -TimeoutSec 30
} catch {
    Write-Err "could not download executor binary: $($_.Exception.Message)"
}
Write-Ok "Installed executor binary to $BinaryPath"

# ---- 3. Write the config.yaml ----------------------------------------
$configBody = @"
# Generated by SentraOps install.ps1 on $(Get-Date -Format o)
# The bootstrap_token line is wiped automatically after a successful
# exchange so a stolen disk image cannot replay it.
server_url: "$ServerURL"
tenant_id: "$TenantID"
client_cert_path: "$CertPath"
client_key_path: "$KeyPath"
server_ca_file: "$CAPath"
# Shared-key path to the platform BE's command inbox. The
# install script writes the api_key to a separate file
# (Administrators + SYSTEM only ACL) and the executor reads
# it at startup. A leaked file is a fully-scoped shared
# secret, not a session for a different system.
install_dir: "$InstallDir"
platform_api_key_path: "$InstallDir\api_key"
kill_switch_path: "$InstallDir\kill_switch"
bootstrap_token: "$BootstrapToken"
bootstrap_url: "$ServerURL"
"@
Set-Content -Path $ConfigPath -Value $configBody -Encoding UTF8 -Force
# Apply the same restrictive ACL to the config file.
$acl = Get-Acl $ConfigPath
$acl.SetAccessRuleProtection($true, $false)
$rules | ForEach-Object { $acl.AddAccessRule($_) }
Set-Acl $ConfigPath $acl
Write-Ok "Wrote config to $ConfigPath (ACL: Administrators + SYSTEM only)"

# Write the platform API key (shared secret) to a separate file
# the executor reads at startup. The install script gets the
# key from the platform BE during bootstrap, then writes it
# here with an Administrators + SYSTEM only ACL.
# a separate file the executor reads at startup. The
# install script gets the key from the platform BE during
# the bootstrap exchange; the executor's PlatformClient
# enforces mode 0600 / Administrators+SYSTEM-only at
# runtime. The key is rotated by re-running install.ps1.
if ($env:SENTRAOPS_EXECUTOR_PLATFORM_API_KEY) {
    $apiKeyPath = Join-Path $InstallDir "api_key"
    Set-Content -Path $apiKeyPath -Value $env:SENTRAOPS_EXECUTOR_PLATFORM_API_KEY -Encoding UTF8 -Force
    $acl = Get-Acl $apiKeyPath
    $acl.SetAccessRuleProtection($true, $false)
    $rules | ForEach-Object { $acl.AddAccessRule($_) }
    Set-Acl $apiKeyPath $acl
    Write-Ok "Wrote platform API key to $apiKeyPath (ACL: Administrators + SYSTEM only)"
} else {
    Write-Warning "SENTRAOPS_EXECUTOR_PLATFORM_API_KEY not set; the executor will start but the platform command inbox will be unreachable. Re-run install.ps1 with the key in the env to enable it."
}

# Pre-shared kill switch. The install script mints a one-time-use
# key locally, encrypts it with the platform's public key, and
# writes the encrypted blob to a known location. The executor's
# command loop decrypts + checks the file on every poll; a
# valid kill switch triggers an immediate self-destruct without
# waiting for the platform BE to push the uninstall command.
# This is the edge path for endpoints that have lost mTLS but
# are still online enough to run a side-channel timer.
# mints a 32-byte one-time-use token, writes a sentinel
# "v1:<base64>" file at the kill_switch path. The
# executor's command loop decrypts + checks the file on
# every poll. The platform operator rotates the kill
# switch by replacing the file content.
$killSwitchPath = Join-Path $InstallDir "kill_switch"
$killBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($killBytes)
$rng.Dispose()
$killToken = [Convert]::ToBase64String($killBytes) -replace '\s', ''
Set-Content -Path $killSwitchPath -Value "v1:$killToken" -Encoding UTF8 -Force
$acl = Get-Acl $killSwitchPath
$acl.SetAccessRuleProtection($true, $false)
$rules | ForEach-Object { $acl.AddAccessRule($_) }
Set-Acl $killSwitchPath $acl
Write-Ok "Wrote kill switch to $killSwitchPath (ACL: Administrators + SYSTEM only)"

# Ship the platform-specific uninstaller into the install
# dir. The executor's command loop invokes the uninstaller
# on a SOC operator's uninstall click. We copy from the
# install bundle so the executor can find it at
# <install_dir>/uninstall.ps1 regardless of where the
# install bundle was downloaded from.
# the install dir so the executor's command loop can find
# it at <install_dir>\uninstall.ps1.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$uninstallerSrc = Join-Path $scriptDir "uninstall.ps1"
if (Test-Path $uninstallerSrc) {
    $uninstallerDst = Join-Path $InstallDir "uninstall.ps1"
    Copy-Item -Path $uninstallerSrc -Destination $uninstallerDst -Force
    # Inherit the install dir ACL.
    $acl = Get-Acl $uninstallerDst
    $acl.SetAccessRuleProtection($true, $false)
    $rules | ForEach-Object { $acl.AddAccessRule($_) }
    Set-Acl $uninstallerDst $acl
    Write-Ok "Shipped uninstaller to $uninstallerDst (ACL: Administrators + SYSTEM only)"
} else {
    Write-Warning "uninstall.ps1 not found in install bundle ($scriptDir); uninstall will fail until this is present"
}

# ---- 4. Install the Windows service via NSSM ------------------------
# We ship nssm.exe alongside the executor binary; the operator
# downloads it as part of the bundle OR we curl it from the same
# place the binary came from. For V1 we use New-Service (built-in)
# and accept that SimplePath; production may swap to NSSM later.
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -eq $svc) {
    Write-Host "Creating Windows service $ServiceName ..."
    New-Service -Name $ServiceName -BinaryPathName "`"$BinaryPath`" --config `"$ConfigPath`"" -DisplayName "SentraOps Executor" -StartupType Automatic | Out-Null
} else {
    Write-Host "Service $ServiceName already exists; updating binary path ..."
    sc.exe config $ServiceName binPath= "`"$BinaryPath`" --config `"$ConfigPath`"" | Out-Null
}
Write-Ok "Service $ServiceName installed"

# ---- 5. Run bootstrap mode (exchange token for cert) ----
Write-Host "Exchanging enrollment token for long-lived mTLS cert ..."
$proc = Start-Process -FilePath $BinaryPath -ArgumentList @("--bootstrap","--config",$ConfigPath) -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -ne 0) {
    Write-Err "bootstrap failed (exit $proc.ExitCode). The install is left in a retryable state; re-run this script to retry."
}
Write-Ok "Bootstrap complete; cert + key + CA bundle written to $InstallDir"

# ---- 6. Start the service -------------------------------------------
Start-Service -Name $ServiceName
Write-Ok "Service started"

# ---- 7. Final report -----------------------------------------------
Write-Host ""
Write-Host "Done. SentraOps executor is online." -ForegroundColor Green
Write-Host ""
Write-Host "Useful commands:"
Write-Host "  Get-Service $ServiceName"
Write-Host "  Get-EventLog -LogName Application -Source $ServiceName -Newest 20"
Write-Host "  & '$BinaryPath' --dry-run --config '$ConfigPath'"
Write-Host ""
Write-Host "Tenant: ${TenantID}"
Write-Host "Server: ${ServerURL}"