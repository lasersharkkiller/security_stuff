## Privilege Escalation

```
ProcessCmd CONTAINS anycase "procdump" AND ProcessCmd CONTAINS anycase "lsass"
OR (TgtProcName = "at.exe" AND TgtProcCmdLine ContainsCIS "/interactive ") 
OR ((RegistryKeyPath ContainsCIS "CurrentVersion\Image File Execution Options" AND RegistryKeyPath ContainsCIS ".exe\Debugger") AND (EventType = "Registry Value Create" OR EventType = "Registry Key Create")) 
OR (SrcProcCmdLine ContainsCIS "ms-settings\shell\open\command" OR SrcProcCmdLine ContainsCIS "mscfile\shell\open\command") 
OR (TgtProcDisplayName = "COM Surrogate" AND TgtProcCmdLine ContainsCIS "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}")
OR ((SrcProcCmdScript Contains "COR_" AND SrcProcCmdScript Contains "\Environment") OR RegistryKeyPath Contains "COR_PROFILER_PATH" OR SrcProcCmdScript Contains "$env:COR_")
OR (SrcProcCmdLine ContainsCIS "net localgroup" AND SrcProcCmdLine ContainsCIS "guest /add") OR (SrcProcCmdLine ContainsCIS "net user" AND SrcProcCmdLine ContainsCIS "/active:yes") OR (RegistryKeyPath In Contains ("Terminal Server\AllowTSConnections","Terminal Server\DenyTSConnections") AND EventType In ("Registry Value Create","Registry Value Modified"))
OR (RegistryKeyPath In Contains Anycase ("CurrentVersion\Image File Execution Options","CurrentVersion\SilentProcessExit") AND RegistryKeyPath In Contains Anycase ("GlobalFlag","ReportingMode","MonitorProcess"))
OR (SrcProcCmdLine ContainsCIS "UserInitMprLogonScript" OR (RegistryKeyPath ContainsCIS "UserInitMprLogonScript" AND EventType = "Registry Value Create"))
OR ((TgtProcName = "netsh.exe" AND TgtProcCmdLine ContainsCIS "add helper") OR (RegistryPath ContainsCIS "SOFTWARE\Microsoft\NetSh" AND EventType = "Registry Value Create"))
OR ((FileFullName = "C:\program.exe" AND EventType In ("File Creation","File Modification")) OR TgtProcImagePath = "C:\program.exe")
OR ((SrcProcCmdScript ContainsCIS "Add-Content $profile -Value" AND SrcProcCmdScript ContainsCIS "Start-Process") OR (TgtProcCmdLine ContainsCIS "Add-Content $profile" AND TgtProcCmdLine In Contains Anycase ("Start-Process","& ","cmd.exe /c")))
OR ((TgtProcName = "mavinject.exe" AND TgtProcCmdLine ContainsCIS "/injectrunning") AND (SrcProcName Not In ("AppVClient.exe") AND SrcProcParentName Not In ("smss.exe")))
OR (RegistryKeyPath ContainsCIS "\Control\Lsa\Security Packages" AND (SrcProcName Not In ("services.exe","SetupHost.exe","svchost.exe") AND SrcProcCmdLine Does Not ContainCIS "system32\wsauth.dll") AND srcProcParentName != "XenDesktopVdaSetup.exe")
```
