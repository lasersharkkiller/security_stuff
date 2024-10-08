## Privilege Escalation

### Detect process dumping lsass

Used by various APTs but an example of use with Hafnium Exchange: https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/

```
ProcessCmd CONTAINS anycase "procdump" AND ProcessCmd CONTAINS anycase "lsass"
```

### Find SGID/SUID bit set files

Looks for attempts to locate files with SGID/SUID bit set
Reference: HHGN, Priv Esc Basics

```
TgtProcImagePath endswith "/find" AND TgtProcCmdLine IN contains anycase ("-perm -4000","-perm -2000","-perm 0777","-perm -222","-perm -o w","-perm -o x","-perm -u=s","-perm -g=s")
```

### Bypass User Group Policy by Changing ntuser.dat to ntuser.man

User Group Policy can be bypassed by changing ntuser.man to ntuser.dat: https://news.ycombinator.com/item?id=22363053

```
FileFullName EndsWith "Ntuser.man"
```

### Detect interactive process execution scheduled by AT command.

Nothing added to baseline

```
TgtProcName = "at.exe" AND TgtProcCmdLine ContainsCIS "/interactive "
```

### Detections addition of a debugger process to executables using Image File Execution Options.

Reference: keyboardcrunch

```
(RegistryKeyPath ContainsCIS "CurrentVersion\Image File Execution Options" AND RegistryKeyPath ContainsCIS ".exe\Debugger") AND (EventType = "Registry Value Create" OR EventType = "Registry Key Create")
```

### Bypass User Access Control
Detection of UAC bypass through tampering with Shell Open for .ms-settings or .msc file types. Beyond this Atomic test, and to further UAC bypass detection, the below query includes detection for CMSTPLUA COM interface abuse by GUID. See [Security-in-bits](https://www.securityinbits.com/malware-analysis/uac-bypass-analysis-stage-1-ataware-ransomware-part-2/#footnote) for more info about CMSTPLUA COM abuse.

*Noted issues with Sentinel Agent 4.3.2.86 detecting by registry key. All registry key paths were ControlSet001\Service\bam\State\UserSettings\GUID\...*

Reference: keyboardcrunch

```
(SrcProcCmdLine ContainsCIS "ms-settings\shell\open\command" OR SrcProcCmdLine ContainsCIS "mscfile\shell\open\command") OR (TgtProcDisplayName = "COM Surrogate" AND TgtProcCmdLine ContainsCIS "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}")
```

### COR Profiler: Detection of unmanaged COR profiler hooking of .NET CLR through registry or process command.

Reference: keyboardcrunch

```
(SrcProcCmdScript Contains "COR_" AND SrcProcCmdScript Contains "\Environment") OR RegistryKeyPath Contains "COR_PROFILER_PATH" OR SrcProcCmdScript Contains "$env:COR_"
```

### Enable Guest account with RDP and Admin

Detects enabling of Guest account, adding Guest account to groups, as well as changing of Deny/Allow of Terminal Server connections through Registry changes.
Reference: keyboardcrunch


```
(SrcProcCmdLine ContainsCIS "net localgroup" AND SrcProcCmdLine ContainsCIS "guest /add") OR (SrcProcCmdLine ContainsCIS "net user" AND SrcProcCmdLine ContainsCIS "/active:yes") OR (RegistryKeyPath In Contains ("Terminal Server\AllowTSConnections","Terminal Server\DenyTSConnections") AND EventType In ("Registry Value Create","Registry Value Modified"))
```

### Image File Execution Options Injection

Detection of Image File Execution Options tampering for persistence through Registry monitoring.
Reference: keyboardcrunch

```
RegistryKeyPath In Contains Anycase ("CurrentVersion\Image File Execution Options","CurrentVersion\SilentProcessExit") AND RegistryKeyPath In Contains Anycase ("GlobalFlag","ReportingMode","MonitorProcess")
```

### Ldapsearch (Linux)

Detects use of ldapsearch
Reference: Malware Analysis Report (AR22-270A): https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-270a

```
TgtProcCmdLine contains anycase "ldapsearch" AND NOT (TgtProcCmdLine contains anycase "centrify" OR srcProcName = "splunkd")
```

### Logon Scripts (Windows)

Detects addition of logon scripts through command line or registry methods.
Reference: keyboardcrunch

```
SrcProcCmdLine ContainsCIS "UserInitMprLogonScript" OR (RegistryKeyPath ContainsCIS "UserInitMprLogonScript" AND EventType = "Registry Value Create")
```

### Netsh Helper DLL

Detection of "helper" dlls with network command shell, through command arguments or registry modification.
Reference: keyboardcrunch

```
(TgtProcName = "netsh.exe" AND TgtProcCmdLine ContainsCIS "add helper") OR (RegistryPath ContainsCIS "SOFTWARE\Microsoft\NetSh" AND EventType = "Registry Value Create")
```

### Unquoted Service Path for program.exe

Detects creation or modification of the file at `C:\program.exe` for exploiting unquoted services paths of Program Files folder.
Reference: keyboardcrunch

```
(FileFullName = "C:\program.exe" AND EventType In ("File Creation","File Modification")) OR TgtProcImagePath = "C:\program.exe"
```

### Malicious Process Start Added to Powershell Profile

Detects the addition of process execution strings (`TgtProcCmdLine In Contains Anycase (list)`)to the powershell profile, through CommandLine and CommandScript indicators.
Reference: keyboardcrunch

```
(SrcProcCmdScript ContainsCIS "Add-Content $profile -Value" AND SrcProcCmdScript ContainsCIS "Start-Process") OR (TgtProcCmdLine ContainsCIS "Add-Content $profile" AND TgtProcCmdLine In Contains Anycase ("Start-Process","& ","cmd.exe /c"))
```

### MavInject Process Injection

Detects Process Injection through execution of MavInject, filtering out noisy/expected activity. `SrcProcParentName` filter narrows Cross Process items to HQ results.
Reference: keyboardcrunch

```
(TgtProcName = "mavinject.exe" AND TgtProcCmdLine ContainsCIS "/injectrunning") AND (SrcProcName Not In ("AppVClient.exe") AND SrcProcParentName Not In ("smss.exe"))
```

### Security Support Provider

Detection of changes to Security Support Provider through Registry modification. Filters most standard system changes with `SrcProcName Not In (list)` but there will be some noise from installers.
Reference: keyboardcrunch
Added XenDesktop

```
RegistryKeyPath ContainsCIS "\Control\Lsa\Security Packages" AND (SrcProcName Not In ("services.exe","SetupHost.exe","svchost.exe") AND SrcProcCmdLine Does Not ContainCIS "system32\wsauth.dll") AND srcProcParentName != "XenDesktopVdaSetup.exe"
```




<br><br><br><br>
## Can't Get a Good Baseline On Or Will Take Alot to Baseline

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

### Parent PID Spoofing

Detects parent PID spoofing through Cross Process indicators (SrcProcParentName limits scope heavily) as well as detecting the use of PPID-Spoof powershell script through Command Scripts indicators. Update the `TgtProcName` list to filter noise.

SentinelOne has a bug about cross processes, I suspect this is throwing this rule off.

```
(TgtProcRelation = "not_in_storyline" AND EventType = "Open Remote Process Handle" AND SrcProcParentName In Contains Anycase ("userinit.exe","powershell.exe","cmd.exe") AND TgtProcName != "sihost.exe" And TgtProcIntegrityLevel  != "LOW" AND TgtProcName Not In ("SystemSettings.exe")) OR (SrcProcCmdScript ContainsCIS "PPID-Spoof" AND SrcProcCmdScript ContainsCIS "hSpoofParent = [Kernel32]::OpenProcess")
```

### Detects malicious changes to screensaver through Registry changes, filtering expected processes.

Needs a bit more baselining

```
RegistryKeyPath ContainsCIS "Control Panel\Desktop\SCRNSAVE.EXE" AND (EventType In ("Registry Value Create","Registry Value Modified") AND SrcProcName Not In ("svchost.exe","SetupHost.exe","CcmExec.exe"))
```

### Windows Management Instrumentation Event Subscription

Detect WMI Event Subs using the New-CimInstance cmdlet, through CommandLine and CommandScript indicators.

This one is going to take a good bit of work to baseline

```
SrcProcCmdLine ContainsCIS "New-CimInstance -Namespace root/subscription" OR SrcProcCmdScript ContainsCIS "New-CimInstance -Namespace root/subscription"
```

### Windows Service

Detects creation and modification of windows services through binPath argument to sc.exe.
Needs a good bit to baseline

```
TgtProcName = "sc.exe" AND TgtProcCmdLine Contains "binPath="
```

### Winlogon Helper DLL

Detects Winlogon Helper Dll changes through Registry MetadataIndicator item, as it holds the full registry change info but will only return data of the Indicators object type.
Needs a good bit to baseline

```
IndicatorMetadata In Contains Anycase ("Microsoft\Windows NT\CurrentVersion\Winlogon","Microsoft\Windows NT\CurrentVersion\Winlogon\Notify") AND IndicatorMetadata In Contains Anycase ("logon","Userinit","Shell") AND IndicatorMetadata Does Not ContainCIS "WINDOWS\system32\userinit.exe"
```
