#############################################################
##########################Exercise #1########################
#############################################################

#Array of core services
$strarry = @("smss.exe", "wininit.exe", "runtimebroker.exe","taskhostw.exe","winlogon.exe","csrss.exe","services.exe","svchost.exe","lsaiso.exe","lsass.exe","explorer.exe")

$pickRandom = Get-Random -Minimum 0 -Maximum 10

$Exercise1exe = $strarry[$pickRandom]

#This assume apt170Unsigned.exe is in the same folder as your script
Copy-Item apt170Unsigned.exe $strarry[$pickRandom]
#Run
Start-Sleep -Milliseconds 3000
Invoke-Expression -Command ".\$($Exercise1exe)"
