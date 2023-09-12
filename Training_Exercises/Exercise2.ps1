#############################################################
##########################Exercise #2########################
#############################################################

#Array of baselined services
$strarry = @("AggregatorHost.exe","ApplicationFrameHost.exe","audiodg.exe","Code.exe","com.docker.serviceconhost.exe","csrss.exe","ctfmon.exe","DataExchangeHost.exe","dllhost.exe","dwm.exe","everything.exe","explorer.exe","fontdrvhost.exe","LockApp.exe","lsaiso.exe","lsass.exe","MpCopyAccelerator.exe","msdtc.exe","msedge.exe","msedgewebview2.exe","MsMpEng.exe","NisSrv.exe","powershell.exe","pwsh.exe","Registryruntimebroker.exe","SearchHost.exe","SearchIndexer.exe","SearchProtocolHost.exe","Secure SystemSecurityHealthService.exe","SecurityHealthSystray.exe","services.exe","SgrmBroker.exe","ShellExperienceHost.exe","sihost.exe","smss.exe","spoolsv.exe","StartMenuExperienceHost.exe","svchost.exe","SystemSysmon64.exe","System Idle Processtaskhostw.exe","uhssvc.exe","unsecapp.exe","VGAuthService.exe","vm3dservice.exe","vmcompute.exe","vmtoolsd.exe","Widgets.exe","wininit.exe","winlogon.exe","WmiPrvSE.exe")

$pickRandom = Get-Random -Minimum 0 -Maximum 55

$Exercise2exe = $strarry[$pickRandom]

#This assume putty.exe is in the same folder as your script
Copy-Item putty.exe $strarry[$pickRandom]
#Run
Start-Sleep -Milliseconds 3000
Invoke-Expression -Command ".\$($Exercise2exe)"
