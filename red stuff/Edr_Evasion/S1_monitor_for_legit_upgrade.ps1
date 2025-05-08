# Requires administrative privileges
# WARNING: For red team research or defensive emulation only.

Write-Host "[*] Monitoring for legitimate SentinelOne upgrade attempts..."

# Infinite monitoring loop
while ($true) {
    # Get all running msiexec.exe processes
    $msiProcs = Get-Process -Name "msiexec" -ErrorAction SilentlyContinue

    foreach ($proc in $msiProcs) {
        try {
            # Check command line arguments of each msiexec process
            $cmdline = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)").CommandLine

            # Look for signs that this msiexec is upgrading SentinelOne
            if ($cmdline -match "Sentinel.*\.msi" -or $cmdline -match "SentinelAgent") {
                Write-Host "[+] Detected possible SentinelOne upgrade attempt in PID $($proc.Id):"
                Write-Host "    $cmdline"

                # Kill the process to prevent upgrade
                Stop-Process -Id $proc.Id -Force
                Write-Host "[!] Killed msiexec.exe (PID $($proc.Id))"
            }
        } catch {
            Write-Warning "[-] Error inspecting or killing process: $_"
        }
    }

    Start-Sleep -Seconds 2  # Tune as needed
}
