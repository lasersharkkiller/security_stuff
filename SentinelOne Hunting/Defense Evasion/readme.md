## Defense Evasion

```
CmdLine Contains Anycase "stop WinDefend" OR CmdLine Contains Anycase "delete WinDefend"
OR (CmdLine Contains Anycase "Set-MpPreference -DisableRealtimeMonitoring" AND NOT (SrcProcPublisher = "OPEN TEXT CORPORATION" OR tgtProcImageSha1 = "c8e743f3460c3f9d761492c61acc358f30b24df7" OR SrcProcPublisher = "PHAROS SYSTEMS INTERNATIONAL, INC" ))
```
