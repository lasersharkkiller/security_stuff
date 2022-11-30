## Privilege Escalation

```
(TgtProcName = "at.exe" AND TgtProcCmdLine ContainsCIS "/interactive ") 
OR ((RegistryKeyPath ContainsCIS "CurrentVersion\Image File Execution Options" AND RegistryKeyPath ContainsCIS ".exe\Debugger") AND (EventType = "Registry Value Create" OR EventType = "Registry Key Create")) 
OR ((SrcProcCmdLine ContainsCIS "ms-settings\shell\open\command" OR SrcProcCmdLine ContainsCIS "mscfile\shell\open\command") 
OR (TgtProcDisplayName = "COM Surrogate" AND TgtProcCmdLine ContainsCIS "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"))
OR ((SrcProcCmdScript Contains "COR_" AND SrcProcCmdScript Contains "\Environment") OR RegistryKeyPath Contains "COR_PROFILER_PATH" OR SrcProcCmdScript Contains "$env:COR_")
```
