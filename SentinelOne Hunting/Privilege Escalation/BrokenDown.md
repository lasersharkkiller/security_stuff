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
