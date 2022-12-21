## Defense Evasion

```
(( TgtProcName In Contains Anycase ("bitsadmin.exe","desktopimgdownldr.exe") AND ( TgtProcCmdLine RegExp "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)" OR TgtProcCmdLine ContainsCIS "/setnotifycmdline " ) ) OR ( TgtProcName = "powershell.exe" AND TgtProcCmdLine ContainsCIS "Start-BitsTransfer" ) ) AND SrcProcParentName Not In ("services.exe","smss.exe","wininit.exe") AND NOT SrcProcPublisher = "LENOVO"
OR ((SrcProcCmdLine ContainsCIS "ms-settings\shell\open\command" OR SrcProcCmdLine ContainsCIS "mscfile\shell\open\command") OR (TgtProcDisplayName = "COM Surrogate" AND TgtProcCmdLine ContainsCIS "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"))
OR ((TgtProcName != "certutil.exe" AND TgtProcDisplayName = "CertUtil.exe") OR ( TgtProcDisplayName = "CertUtil.exe" AND (TgtProcCmdLine RegExp "^.*(-decode).*\.(exe)" OR TgtProcCmdLine RegExp "^.*(-encode).*\.(exe)") ))
OR (SrcProcName = "cmstp.exe" AND SrcProcCmdLine RegExp "^.*\.(inf)")
OR ((TgtProcName = "csc.exe" AND SrcProcCmdLine Contains "/target:exe"))
OR ((SrcProcName = "hh.exe" AND EventType = "Open Remote Process Handle") OR (SrcProcName = "hh.exe" AND SrcProcCmdLine RegExp "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)"))
OR (((SrcProcCmdScript Contains "COR_" AND SrcProcCmdScript Contains "\Environment")  OR RegistryKeyPath Contains "COR_PROFILER_PATH" OR SrcProcCmdScript Contains "$env:COR_") AND NOT srcProcCmdLine Contains Anycase "stackify")
OR ((SrcProcName In Contains ("service","chkconfig") AND SrcProcCmdLine In Contains ("off","stop") AND SrcProcCmdLine ContainsCIS "tables") OR (TgtProcName = "systemctl" AND TgtProcCmdLine In Contains ("stop","disable") AND TgtProcCmdLine Contains "firewalld"))
OR (TgtProcName = "netsh.exe" AND TgtProcCmdLine ContainsCIS "state off")
OR ((TgtProcName = "netsh.exe" AND TgtProcCmdLine ContainsCIS "remote desktop" AND TgtProcCmdLine ContainsCIS "enable=Yes") OR (TgtProcName = "netsh.exe" AND TgtProcCmdLine ContainsCIS "file and printer sharing" AND TgtProcCmdLine ContainsCIS "enable=Yes"))
OR (TgtProcName In Contains ("service","chkconfig","systemctl") AND TgtProcCmdLine In Contains ("rsyslog stop","off rsyslog","stop rsyslog","disable rsyslog"))
OR ((TgtProcName = "fltmc.exe" AND TgtProcCmdLine ContainsCIS "unload SysmonDrv") OR (TgtProcName = "sysmon.exe" AND TgtProcCmdLine ContainsCIS "-u"))
OR (TgtProcCmdLine ContainsCIS "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)" OR SrcProcCmdScript ContainsCIS "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")
OR (RegistryPath ContainsCIS "\Microsoft\AMSI\Providers" AND EventType In ("Registry Key Delete","Registry Value Delete"))
OR ((RegistryKeyPath ContainsCIS "Excel\Security" OR RegistryKeyPath ContainsCIS "Excel\Security\ProtectedView") AND RegistryKeyPath In Contains Anycase ("VBAWarnings","DisableInternetFilesInPV","DisableUnsafeLocationsInPV","DisableAttachementsInPV") AND EventType In ("Registry Value Create","Registry Value Modified"))
OR ((TgtProcName = "appcmd.exe" AND TgtProcCmdLine ContainsCIS "/dontLog:true" AND TgtProcCmdLine ContainsCIS "/section:httplogging")
OR (SrcProcCmdLine ContainsCIS "Invoke-Phant0m" OR SrcProcCmdScript ContainsCIS "$Kernel32::TerminateThread($getThread" OR SrcProcCmdScript ContainsCIS "Invoke-Phant0m"))
OR ((SrcProcCmdLine ContainsCIS "net localgroup" AND SrcProcCmdLine ContainsCIS "guest /add") OR (SrcProcCmdLine ContainsCIS "net user" AND SrcProcCmdLine ContainsCIS "/active:yes" AND NOT SrcProcParentName Contains Anycase "pwdspy") OR (RegistryKeyPath In Contains ("Terminal Server\AllowTSConnections","Terminal Server\DenyTSConnections") AND EventType In ("Registry Value Create","Registry Value Modified")))
OR ((SrcProcName = "mshta.exe" and EventType = "Open Remote Process Handle") OR (SrcProcName = "mshta.exe" AND SrcProcCmdLine RegExp "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)"))
OR ((SrcProcCmdScript ContainsCIS "Start-Hollow" AND SrcProcCmdScript ContainsCIS "[Hollow]::NtQueryInformationProcess") OR TgtProcCmdLine ContainsCIS "Start-Hollow")
OR ((TgtProcName = "mavinject.exe" AND TgtProcCmdLine ContainsCIS "/injectrunning") AND (SrcProcName Not In ("AppVClient.exe") AND SrcProcParentName Not In ("smss.exe")))
OR ((FileFullName = "C:\program.exe" AND EventType In ("File Creation","File Modification")) OR TgtProcImagePath = "C:\program.exe")
OR (CmdLine Contains Anycase "stop WinDefend" OR CmdLine Contains Anycase "delete WinDefend")
OR (CmdLine Contains Anycase "Set-MpPreference -DisableRealtimeMonitoring" AND NOT (SrcProcPublisher = "OPEN TEXT CORPORATION" OR tgtProcImageSha1 = "c8e743f3460c3f9d761492c61acc358f30b24df7" OR SrcProcPublisher = "PHAROS SYSTEMS INTERNATIONAL, INC" ))
```
