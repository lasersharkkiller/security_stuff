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

<br><br>
## Can't Get a Good Baseline On

### Application Shimming: Detects application shimming through sdbinst or registry modification.

Couldn't really get a good baseline on this one, I might return to it later on. Baked SAPSetup in though, it is legitamite.

```
(SrcProcName = "sdbinst.exe" and ProcessCmd ContainsCIS ".sdb") OR ((RegistryKeyPath ContainsCIS "AppInit_DLLs" OR RegistryPath  ContainsCIS "AppCompatFlags") AND (EventType = "Registry Value Create" OR EventType = "Registry Value Modified") AND NOT srcProcName In Anycase ("NwSapSetup.exe"))
```
