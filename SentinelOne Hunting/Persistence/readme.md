## Persistence

### Detect exe's added to AppData\Roaming\Appnet

Technique came from analyzing Cybersecurity and Infrastructure Security Agency report 10412261.r2.v1

```
FilePath Contains Anycase "C:\Windows\AppData\Roaming\Appnet" and FilePath Contains Anycase ".exe"
```


### Accessibility Features

Detections addition of a debugger process to executables using Image File Execution Options.
Reference: keyboardcrunch

```
(RegistryKeyPath ContainsCIS "CurrentVersion\Image File Execution Options" AND RegistryKeyPath ContainsCIS ".exe\Debugger") AND (EventType = "Registry Value Create" OR EventType = "Registry Key Create")
```

### AT Scheduled Task

Detect interactive process execution scheduled by AT command.
Reference: keyboardcrunch

```
TgtProcName = "at.exe" AND TgtProcCmdLine ContainsCIS "/interactive "
```

### BITS Jobs

The below query will find and remote content downloads from DesktopImgDownldr or BitsAdmin processes, Start-BitsTransfer cmdlet downloads, and excludes system processes and noise with SrcProcParentName Not In ().
Reference: keyboardcrunch

```
(( TgtProcName In Contains Anycase ("bitsadmin.exe","desktopimgdownldr.exe") AND ( TgtProcCmdLine RegExp "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)" OR TgtProcCmdLine ContainsCIS "/setnotifycmdline " ) ) OR ( TgtProcName = "powershell.exe" AND TgtProcCmdLine ContainsCIS "Start-BitsTransfer" ) ) AND SrcProcParentName Not In ("services.exe","smss.exe","wininit.exe") AND NOT SrcProcPublisher = "LENOVO"
```



<br><br><br><br>
## Can't Get a Good Baseline On Or Will Take Alot to Baseline

### Account Manipulation

Both Atomic tests for account manipulation rely on PowerShell AD module, so we can catch both with one query. We have the query encapsulated so that we can filter it at the end by Parent Process, as some Logon Scripts and Configuration Items (SCOM, SCCM) may also cause noise. You may want to additionally filter out certain SrcProcUser to reduce noise. What cannot be helped, CommandScript detection on import of Powershell AD cmdlets.
Reference: keyboardcrunch

```
( SrcProcCmdLine In Contains Anycase ("New-ADUser","Rename-LocalUser","Set-LocalUser") OR SrcProcCmdScript In Contains Anycase ("New-ADUser","Rename-LocalUser","Set-LocalUser") OR SrcProcCmdLine RegExp "\bAdd-ADGroupMember\b.*\bDomain Admins\b" OR SrcProcCmdScript RegExp "\bAdd-ADGroupMember\b.*\bDomain Admins\b" ) AND SrcProcParentName Not In ("WmiPrvSE.exe","AppVClient.exe","svchost.exe","CompatTelRunner.exe")
```

### Application Shimming

Detects application shimming through sdbinst or registry modification.
Reference: keyboardcrunch

```
(SrcProcName = "sdbinst.exe" and ProcessCmd ContainsCIS ".sdb") OR ((RegistryKeyPath ContainsCIS "AppInit_DLLs" OR RegistryPath  ContainsCIS "AppCompatFlags") AND (EventType = "Registry Value Create" OR EventType = "Registry Value Modified"))
```

### Browser Extension Installation

This query takes a lazy approach to detecting the staging of xpi or crx extension packages for installation within Chrome and Firefox based browsers. Unsure how to filter our extension updates without excluding too much.
Reference: keyboardcrunch

```
( FileFullName RegExp "\bWebstore Downloads\b.*\.(crx)$" OR FileFullName RegExp "\bstaged\b.*\.(xpi)$" ) AND EventType = "File Creation" AND NOT tgtFilePath Contains Anycase "sentinelone_visibility"
```
