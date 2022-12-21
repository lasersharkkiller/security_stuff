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

### Deobfuscate/Decode Files using Certutil

This Atomic tests detections of certutil encoding and decoding of executables, and the replication of certutil for bypassing detection of executable encoding. Our query below will detected renamed certutil through matching of DisplayName, as well as encoding or decoding of exe files.
Reference: keyboardcrunch

```
(TgtProcName != "certutil.exe" AND TgtProcDisplayName = "CertUtil.exe") OR ( TgtProcDisplayName = "CertUtil.exe" AND (TgtProcCmdLine RegExp "^.*(-decode).*\.(exe)" OR TgtProcCmdLine RegExp "^.*(-encode).*\.(exe)") )
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

### Compile After Delivery

Both Atomic tests for this technique leverage csc.exe for compilation of code. The below will detect specific compilation of executables as well as dynamic compilation through detection of csc.exe creating executable files (both dll and exe). Filter noise from later portion of query using SrcProcParentName Not In (). *Note I could not easily baseline the second part of the query, it might be worth revisiting
Reference: keyboardcrunch

```
(TgtProcName = "csc.exe" AND SrcProcCmdLine Contains "/target:exe")
```

### Compiled HTML File

Breaking down the below query, the first section will detect Atomic Test 1 where a malicious chm file spawns a process, whereas the second half of the query detects hh.exe loading a remote payloads.
Reference: keyboardcrunch

```
(SrcProcName = "hh.exe" AND EventType = "Open Remote Process Handle") OR (SrcProcName = "hh.exe" AND SrcProcCmdLine RegExp "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)")
```

### COR Profiler

Detection of unmanaged COR profiler hooking of .NET CLR through registry or process command.
Reference: keyboardcrunch

```
((SrcProcCmdScript Contains "COR_" AND SrcProcCmdScript Contains "\Environment")  OR RegistryKeyPath Contains "COR_PROFILER_PATH" OR SrcProcCmdScript Contains "$env:COR_") AND NOT srcProcCmdLine Contains Anycase "stackify"
```

### Disable Firewall Local

Reference: keyboardcrunch

Atomic #1 - Linux

```
(SrcProcName In Contains ("service","chkconfig") AND SrcProcCmdLine In Contains ("off","stop") AND SrcProcCmdLine ContainsCIS "tables") OR (TgtProcName = "systemctl" AND TgtProcCmdLine In Contains ("stop","disable") AND TgtProcCmdLine Contains "firewalld")
```

Atomic #2 - Disable Defender Firewall

```
TgtProcName = "netsh.exe" AND TgtProcCmdLine ContainsCIS "state off"
```

Atomic #3 - Allow SMB and RDP on Defender Firewall

```
(TgtProcName = "netsh.exe" AND TgtProcCmdLine ContainsCIS "remote desktop" AND TgtProcCmdLine ContainsCIS "enable=Yes") OR (TgtProcName = "netsh.exe" AND TgtProcCmdLine ContainsCIS "file and printer sharing" AND TgtProcCmdLine ContainsCIS "enable=Yes")
```

*Disable local firewall rules #4-6 not easily baselineable, might be worth revisiting


### Disable Tools (or Modify)

Reference: keyboardcrunch

Atomic #1 - Disable Syslog

```
TgtProcName In Contains ("service","chkconfig","systemctl") AND TgtProcCmdLine In Contains ("rsyslog stop","off rsyslog","stop rsyslog","disable rsyslog")
```

Atomic #9 AND #10 - Disable Sysmon

```
(TgtProcName = "fltmc.exe" AND TgtProcCmdLine ContainsCIS "unload SysmonDrv") OR (TgtProcName = "sysmon.exe" AND TgtProcCmdLine ContainsCIS "-u")
```

Atomic #11 - AMSI Bypass - AMSI InitFailed

```
TgtProcCmdLine ContainsCIS "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)" OR SrcProcCmdScript ContainsCIS "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
```

Atomic #12 - AMSI Bypass - Remove AMSI Provider Reg Key

```
RegistryPath ContainsCIS "\Microsoft\AMSI\Providers" AND EventType In ("Registry Key Delete","Registry Value Delete")
```

Atomic #17 - Disable Microsoft Office Security Features

```
(RegistryKeyPath ContainsCIS "Excel\Security" OR RegistryKeyPath ContainsCIS "Excel\Security\ProtectedView") AND RegistryKeyPath In Contains Anycase ("VBAWarnings","DisableInternetFilesInPV","DisableUnsafeLocationsInPV","DisableAttachementsInPV") AND EventType In ("Registry Value Create","Registry Value Modified")
```

### Disable Windows Event Logging

Atomic #1 - Disable IIS Logging
Reference: keyboardcrunch

```
(TgtProcName = "appcmd.exe" AND TgtProcCmdLine ContainsCIS "/dontLog:true" AND TgtProcCmdLine ContainsCIS "/section:httplogging")
OR (SrcProcCmdLine ContainsCIS "Invoke-Phant0m" OR SrcProcCmdScript ContainsCIS "$Kernel32::TerminateThread($getThread" OR SrcProcCmdScript ContainsCIS "Invoke-Phant0m")
```

### Enable Guest account with RDP and Admin

Detects enabling of Guest account, adding Guest account to groups, as well as changing of Deny/Allow of Terminal Server connections through Registry changes.
Reference: keyboardcrunch

```
(SrcProcCmdLine ContainsCIS "net localgroup" AND SrcProcCmdLine ContainsCIS "guest /add") OR (SrcProcCmdLine ContainsCIS "net user" AND SrcProcCmdLine ContainsCIS "/active:yes" AND NOT SrcProcParentName Contains Anycase "pwdspy") OR (RegistryKeyPath In Contains ("Terminal Server\AllowTSConnections","Terminal Server\DenyTSConnections") AND EventType In ("Registry Value Create","Registry Value Modified"))
```

### Mshta

SentinelOne happens to be pretty good at detecting MSHTA attacks, and IndicatorName = "SuspiciousScript" specifically picks out these javascript based attacks very well. The below query will detect mshta.exe spawning processes as well as URLs for remote payloads to be loaded by mshta.
Reference: keyboardcrunch

```
(SrcProcName = "mshta.exe" and EventType = "Open Remote Process Handle") OR (SrcProcName = "mshta.exe" AND SrcProcCmdLine RegExp "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)")
```

### Process Hollowing (Atomic Red)

Detect Process Hollowing using the Start-Hollow powershell script, through CommandLine and CommandScript indicators.

The IndicatorCategory = "Injection" has a lot of noise, but in the future a combination of EventType = "Duplicate Process Handle" AND TgtProcRelation = "storyline_child" joined with some ChildProcCount or CrossProcCount > 0 may help filter the noise.
Reference: keyboardcrunch

```
(SrcProcCmdScript ContainsCIS "Start-Hollow" AND SrcProcCmdScript ContainsCIS "[Hollow]::NtQueryInformationProcess") OR TgtProcCmdLine ContainsCIS "Start-Hollow"
```

### Process Injection

Detects Process Injection through execution of MavInject, filtering out noisy/expected activity. SrcProcParentName filter narrows Cross Process items to HQ results.
Reference: keyboardcrunch

```
(TgtProcName = "mavinject.exe" AND TgtProcCmdLine ContainsCIS "/injectrunning") AND (SrcProcName Not In ("AppVClient.exe") AND SrcProcParentName Not In ("smss.exe"))
```

### Unquoted Service Path for program.exe

Detects creation or modification of the file at C:\program.exe for exploiting unquoted services paths of Program Files folder.
Reference: keyboardcrunch

```
(FileFullName = "C:\program.exe" AND EventType In ("File Creation","File Modification")) OR TgtProcImagePath = "C:\program.exe"
```


### Windows Defender Commands to Stop 

Technique came from analyzing Cybersecurity and Infrastructure Security Agency (CISA) report 10412261.r2.v1

```
CmdLine Contains Anycase "stop WinDefend" OR CmdLine Contains Anycase "delete WinDefend"
```


### Windows Defender Real Time Monitoring Command to Disable 

Technique came from analyzing Cybersecurity and Infrastructure Security Agency (CISA) report 10412261.r2.v1
This rule excludes RightFax

```
CmdLine Contains Anycase "Set-MpPreference -DisableRealtimeMonitoring" AND NOT (SrcProcPublisher = "OPEN TEXT CORPORATION" OR tgtProcImageSha1 = "c8e743f3460c3f9d761492c61acc358f30b24df7" OR SrcProcPublisher = "PHAROS SYSTEMS INTERNATIONAL, INC" )
```
