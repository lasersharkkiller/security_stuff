## Credential Access

### Browser Credentials

Test #1 - Modified SysInternals AccessChk Chrome password collector - To focus on detection, we're looking for AccessChk.exe where the DisplayName does not match that of the original. There's 4X as many Cross_Process objects with this query but none detect the collection of the Chrome password db.
Reference: keyboardcrunch

```
TgtProcName = "accesschk.exe" AND TgtProcDisplayName != "Reports effective permissions for securable objects"
```

### Group Policy Preferences

Detection focuses on sysvol GP Policy xml file enumeration, with findstr or Get-GPPPassword (Alias or CmdScript internal match).
Reference: keyboardcrunch

```
TgtProcCmdline RegExp "^.*\/S cpassword.*\\sysvol\\.*.xml" OR TgtProcCmdline ContainsCIS "Get-GPPPassword" OR SrcProcCmdScript ContainsCIS "Get-ChildItem -Path \"\\$Server\SYSVOL\" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml'"
```

### GUI Input Capture

Focusing here on detecting the Powershell UI.PromptForCredential and GetNetworkCredential().Password in CmdScript or CmdLine.
Reference: keyboardcrunch

```
(TgtProcCmdline ContainsCIS ".UI.PromptForCredential(" AND TgtProcCmdline ContainsCIS  ".GetNetworkCredential().Password") OR (SrcProcCmdScript ContainsCIS ".UI.PromptForCredential(" AND SrcProcCmdScript ContainsCIS  ".GetNetworkCredential().Password")
```

### Lazagne

Test #1 - LaZagne: LaZagne happens to spawn 3 cmd shells to save security, system and sam RegKeys, and the standard compiled release from github will have the original name artifact of lazagne.exe.manifest within the %temp%_MEI?????\lazagne.exe.manifest location.
Reference: keyboardcrunch

```
TgtProcCmdline Contains "reg.exe save hklm\s" OR TgtFilePath Contains "lazagne.exe.manifest"
```

Test #3 - findstr password extraction

```
TgtProcCmdLine ContainsCIS "/si pass" OR TgtProcCmdLine ContainsCIS "-pattern password"
```

### LSA Secrets

For simplicity, we're detecting a Cmdline used for both psexec (the test) as well as direct reg.exe LSA extraction.
Reference: keyboardcrunch

```
TgtProcCmdLine ContainsCIS "save HKLM\security\policy\secrets"
```

### LSASS Memory Dumping

For simplicity, we're detecting a Cmdline used for both psexec (the test) as well as direct reg.exe LSA extraction.
Reference: keyboardcrunch

```
TgtProcCmdline ContainsCIS "-ma lsass.exe" OR TgtProcCmdline ContainsCIS "comsvcs.dll, MiniDump" OR TgtFilePath = "C:\Windows\Temp\dumpert.dmp" OR TgtFilePath RegExp "^.*lsass.*.DMP" OR (SrcProcCmdline ContainsCIS "sekurlsa::minidump" OR SrcProcCmdline ContainsCIS "sekurlsa::logonpasswords") OR SrcProcCmdline ContainsCIS "live lsa"
```

### NTDS Copy

We won't bother detecting VSS copies being created, rather detecting credential file copies. NTDS.dit or SYSTEM whether a VSS copy or not.
Reference: keyboardcrunch

```
SrcProcCmdline RegExp "^.*copy.*\\Windows\\NTDS\\NTDS.dit.*" OR SrcProcCmdline RegExp "^.*copy.*\\Windows\\System32\\config\\SYSTEM .*" OR SrcProcCmdline ContainsCIS "save HKLM\SYSTEM" OR (TgtProcName = "ntdsutil.exe" AND TgtProcCmdline ContainsCIS "ac i ntds") OR (TgtProcName = "mklink.exe" and  TgtProcCmdline RegExp "^.*\/[d,D].*GLOBALROOT\\Device\\HarddiskVolumeShadowCopy.*")
```

### PowerShell Keylogging

I wasn't able to get either copy of the Get-Keystrokes.ps1 to work with powershell, but the below should reliably detect invocation by alias or CmdScript line matching.
Reference: keyboardcrunch

```
TgtProcCmdline ContainsCIS "Get-Keystrokes" OR SrcProcCmdScript ContainsCIS "user32.dll GetAsyncKeyState" OR SrcProcCmdScript ContainsCIS "[Windows.Forms.Keys][Runtime.InteropServices.Marshal]::ReadInt32("
```

### Registry Credential Enumeration

This query detects enumeration and discovery of credentials within the Registry, including Putty sessions.
Reference: keyboardcrunch

```
TgtProcCmdline ContainsCIS "query HKLM /f password /t REG_SZ /s" OR TgtProcCmdline ContainsCIS "query HKCU /f password /t REG_SZ /s" OR TgtProcCmdline ContainsCIS "query HKCU\Software\SimonTatham\PuTTY\Sessions /t REG_SZ /s"
```
