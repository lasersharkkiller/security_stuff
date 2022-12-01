## Privilege Escalation

### Detect interactive process execution scheduled by AT command.

Nothing added to baseline

```
TgtProcName = "at.exe" AND TgtProcCmdLine ContainsCIS "/interactive "
```

### Detections addition of a debugger process to executables using Image File Execution Options.

Nothing added to baseline

```
(RegistryKeyPath ContainsCIS "CurrentVersion\Image File Execution Options" AND RegistryKeyPath ContainsCIS ".exe\Debugger") AND (EventType = "Registry Value Create" OR EventType = "Registry Key Create")
```

### Bypass User Access Control
Detection of UAC bypass through tampering with Shell Open for .ms-settings or .msc file types. Beyond this Atomic test, and to further UAC bypass detection, the below query includes detection for CMSTPLUA COM interface abuse by GUID. See [Security-in-bits](https://www.securityinbits.com/malware-analysis/uac-bypass-analysis-stage-1-ataware-ransomware-part-2/#footnote) for more info about CMSTPLUA COM abuse.

*Noted issues with Sentinel Agent 4.3.2.86 detecting by registry key. All registry key paths were ControlSet001\Service\bam\State\UserSettings\GUID\...*

Nothing added to baseline

```
(SrcProcCmdLine ContainsCIS "ms-settings\shell\open\command" OR SrcProcCmdLine ContainsCIS "mscfile\shell\open\command") OR (TgtProcDisplayName = "COM Surrogate" AND TgtProcCmdLine ContainsCIS "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}")
```

### COR Profiler: Detection of unmanaged COR profiler hooking of .NET CLR through registry or process command.

Nothing added to baseline

```
(SrcProcCmdScript Contains "COR_" AND SrcProcCmdScript Contains "\Environment") OR RegistryKeyPath Contains "COR_PROFILER_PATH" OR SrcProcCmdScript Contains "$env:COR_"
```


<br><br>
## Can't Get a Good Baseline On

### Application Shimming: Detects application shimming through sdbinst or registry modification.

Couldn't really get a good baseline on this one, I might return to it later on. Baked SAPSetup in though, it is legitamite.

```
(SrcProcName = "sdbinst.exe" and ProcessCmd ContainsCIS ".sdb") OR ((RegistryKeyPath ContainsCIS "AppInit_DLLs" OR RegistryPath  ContainsCIS "AppCompatFlags") AND (EventType = "Registry Value Create" OR EventType = "Registry Value Modified") AND NOT srcProcName In Anycase ("NwSapSetup.exe"))
```

### Change Default File Association

Detection of file association changes. Detection by registry is noisy due to problem filtering on registry root, so install/uninstall apps create noise.

Noisy, difficult to baseline. Maybe revisit

```
--- File assoc change by assoc command
TgtProcCmdLine ContainsCIS "assoc" and TgtProcCmdLine RegExp ".*=.*"
```

###  DLL Search Order Hijacking

Detection of DLL search order hijack for AMSI bypass. Search order bypasses can target more than AMSI, so this can be expanded upon greatly by switching the `ContainsCIS` to `In Contains Anycase(dll list)`.

```
(FileFullName ContainsCIS "amsi.dll" AND FileFullName Does Not ContainCIS "System32") AND EventType = "File Creation"
```

###  DLL Search Order Hijacking

Detection of DLL search order hijack for AMSI bypass. Search order bypasses can target more than AMSI, so this can be expanded upon greatly by switching the `ContainsCIS` to `In Contains Anycase(dll list)`.

```
(FileFullName ContainsCIS "amsi.dll" AND FileFullName Does Not ContainCIS "System32") AND EventType = "File Creation"
```
