## Defense Evasion

### BITS Jobs

The below query will find and remote content downloads from DesktopImgDownldr or BitsAdmin processes, Start-BitsTransfer cmdlet downloads, and excludes system processes and noise with SrcProcParentName Not In ().
Reference: keyboardcrunch

```
(( TgtProcName In Contains Anycase ("bitsadmin.exe","desktopimgdownldr.exe") AND ( TgtProcCmdLine RegExp "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)" OR TgtProcCmdLine ContainsCIS "/setnotifycmdline " ) ) OR ( TgtProcName = "powershell.exe" AND TgtProcCmdLine ContainsCIS "Start-BitsTransfer" ) ) AND SrcProcParentName Not In ("services.exe","smss.exe","wininit.exe") AND NOT SrcProcPublisher = "LENOVO"
```


### Bypass UAC

Detection of UAC bypass through tampering with Shell Open for .ms-settings or .msc file types. Beyond this Atomic test, and to further UAC bypass detection, the below query includes detection for CMSTPLUA COM interface abuse by GUID. See Security-in-bits for more info about CMSTPLUA COM abuse.

Noted issues with Sentinel Agent 4.3.2.86 detecting by registry key. All registry key paths were ControlSet001\Service\bam\State\UserSettings\GUID...
Reference: keyboardcrunch

```
(SrcProcCmdLine ContainsCIS "ms-settings\shell\open\command" OR SrcProcCmdLine ContainsCIS "mscfile\shell\open\command") OR (TgtProcDisplayName = "COM Surrogate" AND TgtProcCmdLine ContainsCIS "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}")
```

### Clear Windows Event Logs

Detects the clearing of EventLogs through wevtutil (concise) as well as Clear-EventLog through CommandLine and CommandScript objects. Powershell cmdlet detection returns a lot of noise for the CommandScripts object, so filtering out SrcProcParentName may be required. *Note I had to take out the script part.
Reference: keyboardcrunch

```
(TgtProcName  = "wevtutil.exe" AND TgtProcCmdLine ContainsCIS "cl ") OR (SrcProcCmdLine ContainsCIS "Clear-EventLog" AND SrcProcParentName Not In ("WmiPrvSE.exe","PFERemediation.exe","svchost.exe"))
```

### CMSTP

CMSTP is rarely used within my environment, so the below detection has low false positives without filtering, though you may want to limit query to inf files located in personal/writeable directories.
Reference: keyboardcrunch

```
SrcProcName = "cmstp.exe" AND SrcProcCmdLine RegExp "^.*\.(inf)"
```

### COR Profiler

Detection of unmanaged COR profiler hooking of .NET CLR through registry or process command.
Reference: keyboardcrunch

```
((SrcProcCmdScript Contains "COR_" AND SrcProcCmdScript Contains "\Environment")  OR RegistryKeyPath Contains "COR_PROFILER_PATH" OR SrcProcCmdScript Contains "$env:COR_") AND NOT srcProcCmdLine Contains Anycase "stackify"
```


### Windows Defender Commands to Stop 

Technique came from analyzing Cybersecurity and Infrastructure Security Agency report 10412261.r2.v1

```
CmdLine Contains Anycase "stop WinDefend" OR CmdLine Contains Anycase "delete WinDefend"
```


### Windows Defender Real Time Monitoring Command to Disable 

Technique came from analyzing Cybersecurity and Infrastructure Security Agency report 10412261.r2.v1
This rule excludes RightFax

```
CmdLine Contains Anycase "Set-MpPreference -DisableRealtimeMonitoring" AND NOT (SrcProcPublisher = "OPEN TEXT CORPORATION" OR tgtProcImageSha1 = "c8e743f3460c3f9d761492c61acc358f30b24df7" OR SrcProcPublisher = "PHAROS SYSTEMS INTERNATIONAL, INC" )
```
