<# 
Standalone Sandbox Logger
- Installs Sysmon (if not already installed)
- Installs Winlogbeat (Elastic Beat)
- Logs Application, Security, System, and Sysmon events
- Outputs NDJSON to C:\SandboxLogs
- Runs persistently as a Windows service

Run in elevated PowerShell (Run as Administrator)
#>

param(
  [string]$ElasticVersion = "8.19.0",
  [string]$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip",
  [string]$SysmonConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml",
  [string]$OutDir = "C:\SandboxLogs"
)

$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "❌ Run this script as Administrator."
}

# Allow TLS 1.2+
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# Create working dirs
$Temp = Join-Path $env:TEMP ("sandbox-setup-" + ([Guid]::NewGuid().ToString("N")))
New-Item -ItemType Directory -Force -Path $Temp | Out-Null
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# -------------------------------------------------------------------
# STEP 1: Install Sysmon (if missing)
# -------------------------------------------------------------------
if (-not (Get-Service | Where-Object { $_.Name -eq "Sysmon" })) {
  Write-Host "==> Downloading Sysmon ..." -ForegroundColor Cyan
  $sysmonZip = Join-Path $Temp "Sysmon.zip"
  Invoke-WebRequest -Uri $SysmonUrl -OutFile $sysmonZip -UseBasicParsing
  Expand-Archive -Path $sysmonZip -DestinationPath $Temp -Force

  $sysmonExe = Get-ChildItem $Temp -Filter "Sysmon64.exe" -Recurse | Select-Object -First 1
  if (-not $sysmonExe) { throw "Could not find Sysmon64.exe after extraction!" }

  Write-Host "==> Fetching Sysmon config ..." -ForegroundColor Cyan
  $sysmonConfig = Join-Path $Temp "sysmonconfig.xml"
  Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $sysmonConfig -UseBasicParsing

  Write-Host "==> Installing Sysmon ..." -ForegroundColor Green
  & $sysmonExe.FullName -accepteula -i $sysmonConfig
} else {
  Write-Host "✅ Sysmon already installed." -ForegroundColor Green
}

# -------------------------------------------------------------------
# STEP 2: Install Winlogbeat (standalone)
# -------------------------------------------------------------------
$artifact = "winlogbeat-$ElasticVersion-windows-x86_64.zip"
$beatsUrl = "https://artifacts.elastic.co/downloads/beats/winlogbeat/$artifact"
$zip = Join-Path $Temp $artifact
$extract = Join-Path $Temp "winlogbeat-$ElasticVersion-windows-x86_64"
$installDir = "C:\Program Files\Winlogbeat"

Write-Host "==> Downloading Winlogbeat $ElasticVersion ..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $beatsUrl -OutFile $zip -UseBasicParsing
Expand-Archive -Path $zip -DestinationPath $Temp -Force

if (Test-Path $installDir) {
  Write-Host "==> Removing existing Winlogbeat ..." -ForegroundColor Yellow
  try { Stop-Service winlogbeat -Force -ErrorAction SilentlyContinue } catch {}
  Start-Sleep 1
  try { & "$installDir\uninstall-service-winlogbeat.ps1" } catch {}
  Remove-Item -Recurse -Force $installDir
}
Copy-Item -Recurse -Force -Path (Join-Path $extract "*") -Destination $installDir

# -------------------------------------------------------------------
# STEP 3: Configure Winlogbeat for NDJSON local logging
# -------------------------------------------------------------------
$yml = @"
winlogbeat.event_logs:
  - name: Application
  - name: System
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational

processors:
  - add_host_metadata: ~
  - add_process_metadata: ~

output.file:
  path: "$OutDir"
  filename: "events"
  rotate_every_kb: 1048576
  number_of_files: 100
  codec.json:
    pretty: false
    escape_html: false

logging.level: info
logging.to_files: true
logging.files:
  path: "$OutDir\winlogbeat-internal"
"@

$cfgPath = Join-Path $installDir "winlogbeat.yml"
$yml | Set-Content -Encoding UTF8 -Path $cfgPath -NoNewline

Write-Host "==> Installing Winlogbeat as service ..." -ForegroundColor Cyan
& "$installDir\install-service-winlogbeat.ps1"

Write-Host "==> Starting Winlogbeat service ..." -ForegroundColor Green
Start-Service winlogbeat

# -------------------------------------------------------------------
# STEP 4: Confirm setup
# -------------------------------------------------------------------
Write-Host "`n✅ Installation complete!" -ForegroundColor Green
Write-Host "Sysmon: Installed and running"
Write-Host "Winlogbeat: Running as service (persistent)"
Write-Host "Logs directory: $OutDir"
Write-Host "`nTo check logs: Get-Content -Wait '$OutDir\winlogbeat-internal\winlogbeat'`"
Write-Host "To stop Winlogbeat: Stop-Service winlogbeat"
Write-Host "To uninstall: & 'C:\Program Files\Winlogbeat\uninstall-service-winlogbeat.ps1'"
Write-Host "To remove Sysmon: sysmon64.exe -u"
