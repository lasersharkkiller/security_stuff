## Credential Access

```
TgtProcName = "accesschk.exe" AND TgtProcDisplayName != "Reports effective permissions for securable objects"
OR (TgtProcCmdline RegExp "^.*\/S cpassword.*\\sysvol\\.*.xml" OR TgtProcCmdline ContainsCIS "Get-GPPPassword" OR SrcProcCmdScript ContainsCIS "Get-ChildItem -Path \"\\$Server\SYSVOL\" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml'")
OR ((TgtProcCmdline ContainsCIS ".UI.PromptForCredential(" AND TgtProcCmdline ContainsCIS  ".GetNetworkCredential().Password") OR (SrcProcCmdScript ContainsCIS ".UI.PromptForCredential(" AND SrcProcCmdScript ContainsCIS  ".GetNetworkCredential().Password"))
OR (TgtProcCmdline Contains "reg.exe save hklm\s" OR TgtFilePath Contains "lazagne.exe.manifest")
OR (TgtProcCmdLine ContainsCIS "/si pass" OR TgtProcCmdLine ContainsCIS "-pattern password")
OR (TgtProcCmdLine ContainsCIS "save HKLM\security\policy\secrets")
OR (RegistryKeyPath contains anycase "Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe")
OR (TgtProcCmdline ContainsCIS "-ma lsass.exe" OR TgtProcCmdline ContainsCIS "comsvcs.dll, MiniDump" OR TgtFilePath = "C:\Windows\Temp\dumpert.dmp" OR TgtFilePath RegExp "^.*lsass.*.DMP" OR (SrcProcCmdline ContainsCIS "sekurlsa::minidump" OR SrcProcCmdline ContainsCIS "sekurlsa::logonpasswords") OR SrcProcCmdline ContainsCIS "live lsa")
OR (SrcProcCmdline RegExp "^.*copy.*\\Windows\\NTDS\\NTDS.dit.*" OR SrcProcCmdline RegExp "^.*copy.*\\Windows\\System32\\config\\SYSTEM .*" OR SrcProcCmdline ContainsCIS "save HKLM\SYSTEM" OR (TgtProcName = "ntdsutil.exe" AND TgtProcCmdline ContainsCIS "ac i ntds") OR (TgtProcName = "mklink.exe" and  TgtProcCmdline RegExp "^.*\/[d,D].*GLOBALROOT\\Device\\HarddiskVolumeShadowCopy.*"))
OR (TgtProcCmdline ContainsCIS "Get-Keystrokes" OR SrcProcCmdScript ContainsCIS "user32.dll GetAsyncKeyState" OR SrcProcCmdScript ContainsCIS "[Windows.Forms.Keys][Runtime.InteropServices.Marshal]::ReadInt32(")
OR (TgtProcCmdline ContainsCIS "query HKLM /f password /t REG_SZ /s" OR TgtProcCmdline ContainsCIS "query HKCU /f password /t REG_SZ /s" OR TgtProcCmdline ContainsCIS "query HKCU\Software\SimonTatham\PuTTY\Sessions /t REG_SZ /s")
```
