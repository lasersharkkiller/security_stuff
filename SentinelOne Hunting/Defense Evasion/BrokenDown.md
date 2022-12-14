## Defense Evasion

### Commands to Stop Windows Defender

Technique came from analyzing Cybersecurity and Infrastructure Security Agency report 10412261.r2.v1

```
CmdLine Contains Anycase "stop WinDefend" OR CmdLine Contains Anycase "delete WinDefend"
```

### Command to Disable Windows Defender Real Time Monitoring

Technique came from analyzing Cybersecurity and Infrastructure Security Agency report 10412261.r2.v1
This rule excludes RightFax

```
CmdLine Contains Anycase "Set-MpPreference -DisableRealtimeMonitoring" AND NOT (SrcProcPublisher = "OPEN TEXT CORPORATION" OR tgtProcImageSha1 = "c8e743f3460c3f9d761492c61acc358f30b24df7" OR SrcProcPublisher = "PHAROS SYSTEMS INTERNATIONAL, INC" )
```
