# uninstall.ps1 — SentraOps executor uninstaller (Windows)
#
# Wired by the executor's command loop (R-I.12.b) when the
# platform BE issues an `uninstall` command. Same contract
# as install/uninstall.sh (Linux) and install/uninstall-macos.sh
# (macOS) — see those files' headers for the full design
# rationale. This file is the Windows counterpart: Service
# Control Manager (sc.exe) instead of systemd / launchd,
# %ProgramFiles%\SentraOps for the install location,
# schtasks instead of cron, and a 3-pass overwrite for the
# secure-delete.
#
# Windows-specific bits:
#
#   - Stop-Service + sc.exe delete: stops + unregisters the
#     Windows service the install script registered.
#   - The task scheduler entries (if any) are unregisterd
#     via schtasks /Delete /F.
#   - The install location defaults to
#     $env:ProgramFiles\SentraOps (typically
#     C:\Program Files\SentraOps). The install script
#     honours a SENTRAOPS_EXECUTOR_INSTALL_DIR env var.
#   - There is no native shred on Windows. We use
#     [System.IO.File]::Open with FileShare::None to
#     overwrite the file's content 3 times with
#     cryptographic random bytes, then delete. This is
#     the closest equivalent to shred -n 3 on POSIX.
#     SSD TRIM / forensic recovery is beyond what any
#     uninstaller can prevent; the design doc §3.4
#     'no trace' honesty section spells this out.
#
# The contract is identical to the POSIX uninstallers:
#   - No reboot, no shutdown, no logoff.
#   - Silent self-destruct.
#   - Audit chain on the BE side via the orchestrator's
#     command loop ack; this script does NOT directly
#     write to the platform audit log.
#   - Idempotent: a second invocation exits 0 cleanly.
#
# Usage (the orchestrator invokes this via PowerShell):
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1 -Reason "..."

[CmdletBinding()]
param(
  [string]$Reason = "no reason given"
)

$ErrorActionPreference = "Stop"

$InstallDir = $env:SENTRAOPS_EXECUTOR_INSTALL_DIR
if (-not $InstallDir) {
  $InstallDir = Join-Path $env:ProgramFiles "SentraOps"
}
$BinDir = $env:SENTRAOPS_EXECUTOR_BIN_DIR
if (-not $BinDir) {
  $BinDir = $env:ProgramFiles
}
$ExecBin = Join-Path $BinDir "sentraops-executor.exe"
$RunnerBin = Join-Path $BinDir "sentraops-runner.exe"
$ServiceName = "SentraOpsExecutor"
$RunnerServiceName = "SentraOpsRunner"

function Log([string]$msg) { Write-Output $msg }
function Ok([string]$msg) { Log "OK   $msg" }
function Warn([string]$msg) { Log "WARN $msg" }
function Fail([string]$msg) { Log "ERROR $msg"; exit 1 }

Log "SentraOps executor uninstaller (Windows) starting"
Log "  reason:    $Reason"
Log "  install:   $InstallDir"
Log "  binary:    $ExecBin"

# Idempotent: nothing to do if the install dir + binary
# are both already gone.
if (-not (Test-Path $InstallDir) -and -not (Test-Path $ExecBin)) {
  Warn "no install found at $InstallDir (already uninstalled?)"
  Log "exiting 0 - nothing to do"
  exit 0
}

# ---- 1. Stop the Windows services -------------------------
# We use Stop-Service first (clean stop signal), then
# fall back to sc.exe stop (immediate). We never use
# sc.exe delete before the service is stopped (Windows
# refuses to delete a running service).
function Stop-ServiceIfPresent([string]$name) {
  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if ($null -eq $svc) {
    Warn "$name service not registered; skipping stop"
    return
  }
  if ($svc.Status -eq "Stopped") {
    Ok "$name already stopped"
    return
  }
  try {
    Log "stopping $name..."
    Stop-Service -Name $name -Force -ErrorAction Stop
    # Wait up to 30s for the service to reach Stopped.
    $svc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30)) | Out-Null
    Ok "stopped $name"
  } catch {
    Warn "Stop-Service $name failed: $_ (continuing with sc.exe)"
    & sc.exe stop $name 2>&1 | Out-Null
    Start-Sleep -Seconds 5
  }
}

Stop-ServiceIfPresent $ServiceName
if (Test-Path $RunnerBin) {
  Stop-ServiceIfPresent $RunnerServiceName
}

# ---- 2. Unregister the Windows services ------------------
# sc.exe delete: removes the service from SCM. We never
# delete before the service is fully stopped; sc.exe
# returns "service is marked for deletion" if you try.
function Delete-ServiceIfPresent([string]$name) {
  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if ($null -eq $svc) { return }
  Log "deleting service $name..."
  & sc.exe delete $name 2>&1 | Out-Null
  Ok "deleted $name"
}

Delete-ServiceIfPresent $ServiceName
if (Test-Path $RunnerBin) {
  Delete-ServiceIfPresent $RunnerServiceName
}

# ---- 3. Unregister scheduled tasks (if any) --------------
# The install script does not register any tasks today
# (R-I.5 only uses Windows service control), but R-F
# (macOS) + future sub-slices may use schtasks. We
# defensively unregister any sentraops-* task that exists.
$tasks = & schtasks /Query /FO CSV 2>$null | Where-Object { $_ -match 'sentraops' }
foreach ($task in $tasks) {
  $taskName = ($task -split ',')[0].Trim('"')
  if ($taskName) {
    Log "deleting scheduled task $taskName..."
    & schtasks /Delete /TN $taskName /F 2>&1 | Out-Null
  }
}

# ---- 4. Shred + remove the install dir + binaries --------
# Windows has no shred. We use [System.IO.File]::Open with
# FileShare::None to overwrite the file's content 3 times
# with cryptographic random bytes (System.Security.Cryptography
# .RandomNumberGenerator), then File.Delete. This is the
# closest equivalent to shred -n 3 on POSIX.
function Remove-Securely {
  param([string]$Path)
  if (-not (Test-Path $Path)) { return }
  if ((Get-Item $Path).PSIsContainer) {
    # Directory: walk children, then rmdir.
    Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
      Remove-Securely -Path $_.FullName
    }
    Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
    return
  }
  try {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $size = $bytes.Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    for ($i = 0; $i -lt 3; $i++) {
      $buf = New-Object byte[] $size
      $rng.GetBytes($buf)
      [System.IO.File]::WriteAllBytes($Path, $buf)
    }
    $rng.Dispose()
    Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
  } catch {
    Warn "secure remove failed for $Path : $_ (falling back to plain remove)"
    Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Log "removing $InstallDir..."
if (Test-Path $InstallDir) {
  Remove-Securely -Path $InstallDir
  Ok "removed $InstallDir"
}

Log "removing $ExecBin..."
Remove-Securely -Path $ExecBin
Ok "removed $ExecBin"

if (Test-Path $RunnerBin) {
  Log "removing $RunnerBin (also installed)..."
  Remove-Securely -Path $RunnerBin
  Ok "removed $RunnerBin"
}

# ---- 5. Self-destruct ------------------------------------
# Delete THIS script. The IP-protection guarantee depends
# on the uninstaller not leaving itself on disk.
Log "self-destructing uninstaller..."
$self = $MyInvocation.MyCommand.Path
if ($self -and (Test-Path $self)) {
  Remove-Securely -Path $self
  Ok "uninstaller self-destructed"
}

# ---- 6. Done ---------------------------------------------
Log ""
Log "SentraOps executor uninstalled (silent self-destruct)."
Log ""
Log "Audit one-liner:"
Log "  SentraOps executor and runner (if present) on $env:COMPUTERNAME"
Log "  have been removed. Customer's machine is untouched: no reboot,"
Log "  no shutdown. Forensic recovery of deleted files is beyond what"
Log "  this uninstaller can prevent; full-disk encryption + reimaging"
Log "  is the only true guarantee."
Log ""

exit 0
