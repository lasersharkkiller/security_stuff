<#
Safe Emulation Helper - Non-destructive
Purpose: execute discovery/collection commands (read-only) and capture outputs to local folder.
DO NOT run on production. Use only in an isolated, authorized test lab.
#>

$OutputDir = "$env:LOCALAPPDATA\edr_emulation_output"
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

Function Save-Output($name, $content) {
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $file = Join-Path $OutputDir ("{0}_{1}.txt" -f $name, $ts)
    $content | Out-File -FilePath $file -Encoding utf8
    Write-Output "Saved: $file"
}

# 1) Process & services (tasklist /svc)
try {
    $tasklist = cmd.exe /c "tasklist /svc" 2>&1
    Save-Output -name "tasklist_svc" -content $tasklist
} catch {
    Save-Output -name "tasklist_svc_error" -content $_.ToString()
}

# 2) Disk information via WMIC (logical disk)
try {
    $wmic = wmic logicaldisk get DeviceID,Size,FreeSpace,FileSystem /format:list 2>&1
    Save-Output -name "wmic_logicaldisk" -content $wmic
} catch {
    Save-Output -name "wmic_logicaldisk_error" -content $_.ToString()
}

# 3) Domain / local users (net user; whoami /groups)
try {
    $netusers = cmd.exe /c "net user" 2>&1
    Save-Output -name "net_user" -content $netusers

    $whoami = whoami /all 2>&1
    Save-Output -name "whoami_all" -content $whoami
} catch {
    Save-Output -name "net_user_error" -content $_.ToString()
}

# 4) System info
try {
    $sysinfo = systeminfo 2>&1
    Save-Output -name "systeminfo" -content $sysinfo
} catch {
    Save-Output -name "systeminfo_error" -content $_.ToString()
}

# 5) AD enumeration (only run if in test AD and you have rights) - use nltest /whoami as a read-only step
try {
    $domain = (Get-WmiObject Win32_ComputerSystem).Domain
    Save-Output -name "domain_info" -content $domain
} catch {
    Save-Output -name "domain_info_error" -content $_.ToString()
}

# 6) Screen capture (using built-in .NET, saves to local folder) - small and non-exfiltrating
try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $bitmap = New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,
                                              [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen(0,0,0,0,$bitmap.Size)
    $screenshotPath = Join-Path $OutputDir ("screenshot_{0}.png" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $bitmap.Save($screenshotPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    $bitmap.Dispose()
    Write-Output "Saved screenshot: $screenshotPath"
} catch {
    Save-Output -name "screenshot_error" -content $_.ToString()
}

# Wrap up
Write-Output "Emulation helper finished. Outputs in: $OutputDir"
