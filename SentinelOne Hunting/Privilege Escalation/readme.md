## Privilege Escalation

```
(TgtProcName = "at.exe" AND TgtProcCmdLine ContainsCIS "/interactive ") OR ((RegistryKeyPath ContainsCIS "CurrentVersion\Image File Execution Options" AND RegistryKeyPath ContainsCIS ".exe\Debugger") AND (EventType = "Registry Value Create" OR EventType = "Registry Key Create"))
```
