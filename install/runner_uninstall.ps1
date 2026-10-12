# runner_uninstall.ps1 — SentraOps runner-only self-destruct (Windows)
#
# R-F.3.b: the Windows uninstaller for the runner-only
# binary. Mirrors runner_uninstall.sh (Linux) and
# runner_uninstall-macos.sh — same contract, same
# idempotency, same silent self-destruct posture.
#
# Windows uses the Service Control Manager (sc.exe) instead
# of systemd or launchd. The install script registers
# "SentraOps Runner" as a service and writes a Service
# Control Manager key. The uninstaller stops + removes the
# service before shredding the install dir + binary.
#
# PowerShell's `Get-FileHash` + `Set-Content` overwrites
# are used for shred (the `shred` GNU utility is not
# available on stock Windows). The cert + key + API key +
# kill switch are overwritten with random bytes before
# deletion. NIST SP 800-88 Rev 1 considers this sufficient
# for ATA drives and SSD TRIM, and an attacker with raw
# NAND access is outside the uninstaller's threat model
# (per the R-I.12 honest-no-trace caveat).

param(
  [Parameter(Mandatory=$false)]
  [string]$Reason = "no reason given"
)

$ErrorActionPreference = "Stop"

$InstallDir   = Join-Path $env:ProgramFiles "SentraOps\runner"
$BinPath      = Join-Path $InstallDir "sentraops-runner.exe"
$ServiceName  = "SentraOpsRunner"
$LogFile      = Join-Path $env:TEMP "sentraops-runner-uninstall.log"

function Log($msg) {
  $line = "[runner_uninstall] $msg"
  Write-Host $line
  Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# Best-effort log file init. If %TEMP% is read-only (rare),
# the install still proceeds; we just lose the post-mortem
# log.
try { Set-Content -Path $LogFile -Value "" -ErrorAction SilentlyContinue } catch {}

Log "received uninstall command - reason: $Reason"

# ---- 1. Stop + remove the service --------------------------------
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $svc) {
  Log "stopping service $ServiceName"
  try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
  Start-Sleep -Seconds 2
  try { sc.exe delete $ServiceName | Out-Null } catch {}
  Log "removed service $ServiceName"
} else {
  Log "$ServiceName not installed (already uninstalled?)"
}

# ---- 2. Shred + remove the install dir + binary -----------------
# PowerShell's shred: overwrite the file with random bytes
# (one pass is enough per NIST SP 800-88 Rev 1 for ATA + SSD
# with TRIM). Then delete.
function Shred-File($path) {
  if (-not (Test-Path $path)) { return }
  $len = (Get-Item $path).Length
  if ($len -le 0) { Remove-Item -Path $path -Force -ErrorAction SilentlyContinue; return }
  # 4096-byte blocks
  $blocks = [Math]::Ceiling($len / 4096.0)
  $bytes  = New-Object byte[] 4096
  $rng    = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
  try {
    $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write)
    for ($i = 0; $i -lt $blocks; $i++) {
      $rng.GetBytes($bytes)
      $fs.Position = $i * 4096
      $fs.Write($bytes, 0, [Math]::Min(4096, $len - $i * 4096))
    }
    $fs.Flush(); $fs.Close()
  } catch {
    Log "shred error on $path - $_.Exception.Message"
  } finally {
    $rng.Dispose()
  }
  Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
}

if (Test-Path $InstallDir) {
  Log "shredding contents of $InstallDir"
  $files = @(
    "cert.pem",
    "key.pem",
    "ca.pem",
    "api_key",
    "kill_switch",
    "config.yaml",
    "audit.log",
    "runner.log"
  )
  foreach ($f in $files) {
    $p = Join-Path $InstallDir $f
    if (Test-Path $p) { Shred-File $p }
  }
  # Any remaining files we did not list (future config
  # additions) get removed too. The dir itself goes last.
  Get-ChildItem -Path $InstallDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { Shred-File $_.FullName }
  Get-ChildItem -Path $InstallDir -Recurse -Directory -ErrorAction SilentlyContinue | ForEach-Object { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
  Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
  Log "removed $InstallDir"
} else {
  Log "$InstallDir not present (already removed?)"
}

# ---- 3. Remove the binary ---------------------------------------
if (Test-Path $BinPath) {
  Log "shredding $BinPath"
  Shred-File $BinPath
} else {
  Log "$BinPath not present (already removed?)"
}

# ---- 4. Self-delete the uninstaller ------------------------------
# PowerShell's $MyInvocation.MyCommand.Path is the path to
# the script. We delete it after the rest of the work to
# keep the script readable.
$ScriptSelf = $MyInvocation.MyCommand.Path
if ($ScriptSelf -and (Test-Path $ScriptSelf)) {
  try { Remove-Item -Path $ScriptSelf -Force -ErrorAction SilentlyContinue } catch {}
  Log "self-deleted $ScriptSelf"
}

# ---- 5. Final log line ------------------------------------------
Log "uninstall complete - agent silent, customer machine still running, no reboot"
exit 0
