## Persistence

```
FilePath Contains Anycase "C:\Windows\AppData\Roaming\Appnet" and FilePath Contains Anycase ".exe"
OR ((RegistryKeyPath ContainsCIS "CurrentVersion\Image File Execution Options" AND RegistryKeyPath ContainsCIS ".exe\Debugger") AND (EventType = "Registry Value Create" OR EventType = "Registry Key Create"))
OR (TgtProcName = "at.exe" AND TgtProcCmdLine ContainsCIS "/interactive ")
OR ((( TgtProcName In Contains Anycase ("bitsadmin.exe","desktopimgdownldr.exe") AND ( TgtProcCmdLine RegExp "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)" OR TgtProcCmdLine ContainsCIS "/setnotifycmdline " ) ) OR ( TgtProcName = "powershell.exe" AND TgtProcCmdLine ContainsCIS "Start-BitsTransfer" ) ) AND SrcProcParentName Not In ("services.exe","smss.exe","wininit.exe") AND NOT SrcProcPublisher = "LENOVO")
OR (((SrcProcCmdScript Contains "COR_" AND SrcProcCmdScript Contains "\Environment")  OR RegistryKeyPath Contains "COR_PROFILER_PATH" OR SrcProcCmdScript Contains "$env:COR_") AND NOT srcProcCmdLine Contains Anycase "stackify")
OR (SrcProcCmdLine ContainsCIS "UserInitMprLogonScript" OR (RegistryKeyPath ContainsCIS "UserInitMprLogonScript" AND EventType = "Registry Value Create"))
OR ((TgtProcName = "netsh.exe" AND TgtProcCmdLine ContainsCIS "add helper") OR (RegistryPath ContainsCIS "SOFTWARE\Microsoft\NetSh" AND EventType = "Registry Value Create"))
OR ((FileFullName = "C:\program.exe" AND EventType In ("File Creation","File Modification")) OR TgtProcImagePath = "C:\program.exe")
OR ((SrcProcCmdScript ContainsCIS "Add-Content $profile -Value" AND SrcProcCmdScript ContainsCIS "Start-Process") OR (TgtProcCmdLine ContainsCIS "Add-Content $profile" AND TgtProcCmdLine In Contains Anycase ("Start-Process","& ","cmd.exe /c")))
```
