## Persistence

### Detect exe's added to AppData\Roaming\Appnet

Technique came from analyzing Cybersecurity and Infrastructure Security Agency report 10412261.r2.v1

```
FilePath Contains Anycase "C:\Windows\AppData\Roaming\Appnet" and FilePath Contains Anycase ".exe"
```


### Accessibility Features

Detections addition of a debugger process to executables using Image File Execution Options.
Reference: keyboardcrunch

```
(RegistryKeyPath ContainsCIS "CurrentVersion\Image File Execution Options" AND RegistryKeyPath ContainsCIS ".exe\Debugger") AND (EventType = "Registry Value Create" OR EventType = "Registry Key Create")
```

### AT Scheduled Task

Detect interactive process execution scheduled by AT command.
Reference: keyboardcrunch

```
TgtProcName = "at.exe" AND TgtProcCmdLine ContainsCIS "/interactive "
```

### BITS Jobs

The below query will find and remote content downloads from DesktopImgDownldr or BitsAdmin processes, Start-BitsTransfer cmdlet downloads, and excludes system processes and noise with SrcProcParentName Not In ().
Reference: keyboardcrunch

```
(( TgtProcName In Contains Anycase ("bitsadmin.exe","desktopimgdownldr.exe") AND ( TgtProcCmdLine RegExp "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)" OR TgtProcCmdLine ContainsCIS "/setnotifycmdline " ) ) OR ( TgtProcName = "powershell.exe" AND TgtProcCmdLine ContainsCIS "Start-BitsTransfer" ) ) AND SrcProcParentName Not In ("services.exe","smss.exe","wininit.exe") AND NOT SrcProcPublisher = "LENOVO"
```

### COR Profiler

Detection of unmanaged COR profiler hooking of .NET CLR through registry or process command.
Reference: keyboardcrunch

```
((SrcProcCmdScript Contains "COR_" AND SrcProcCmdScript Contains "\Environment")  OR RegistryKeyPath Contains "COR_PROFILER_PATH" OR SrcProcCmdScript Contains "$env:COR_") AND NOT srcProcCmdLine Contains Anycase "stackify"
```

### Logon Scripts

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

Detects creation or modification of the file at C:\program.exe for exploiting unquoted services paths of Program Files folder.
Reference: keyboardcrunch

```
(FileFullName = "C:\program.exe" AND EventType In ("File Creation","File Modification")) OR TgtProcImagePath = "C:\program.exe"
```

### Malicious Process Start Added to Powershell Profile

Detects the addition of process execution strings (TgtProcCmdLine In Contains Anycase (list))to the powershell profile, through CommandLine and CommandScript indicators.
Reference: keyboardcrunch

```
(SrcProcCmdScript ContainsCIS "Add-Content $profile -Value" AND SrcProcCmdScript ContainsCIS "Start-Process") OR (TgtProcCmdLine ContainsCIS "Add-Content $profile" AND TgtProcCmdLine In Contains Anycase ("Start-Process","& ","cmd.exe /c"))
```

### Transport Agent

Detection of Powershell TransportAgent Cmdlets being used to setup an Exchange Transport Agent.
Reference: keyboardcrunch

```
SrcProcCmdLine In Contains Anycase ("Install-TransportAgent","Enable-TransportAgent","Get-TransportAgent") OR SrcProcCmdScript In Contains Anycase ("Install-TransportAgent","Enable-TransportAgent","Get-TransportAgent")
```

### Windows Management Instrumentation Event Subscription

Detect WMI Event Subs using the New-CimInstance cmdlet, through CommandLine and CommandScript indicators.
Reference: keyboardcrunch

```
SrcProcCmdLine ContainsCIS "New-CimInstance -Namespace root/subscription" OR SrcProcCmdScript ContainsCIS "New-CimInstance -Namespace root/subscription"
```








<br><br><br><br>
## Can't Get a Good Baseline On Or Will Take Alot to Baseline

### Account Manipulation

Both Atomic tests for account manipulation rely on PowerShell AD module, so we can catch both with one query. We have the query encapsulated so that we can filter it at the end by Parent Process, as some Logon Scripts and Configuration Items (SCOM, SCCM) may also cause noise. You may want to additionally filter out certain SrcProcUser to reduce noise. What cannot be helped, CommandScript detection on import of Powershell AD cmdlets.
Reference: keyboardcrunch

```
( SrcProcCmdLine In Contains Anycase ("New-ADUser","Rename-LocalUser","Set-LocalUser") OR SrcProcCmdScript In Contains Anycase ("New-ADUser","Rename-LocalUser","Set-LocalUser") OR SrcProcCmdLine RegExp "\bAdd-ADGroupMember\b.*\bDomain Admins\b" OR SrcProcCmdScript RegExp "\bAdd-ADGroupMember\b.*\bDomain Admins\b" ) AND SrcProcParentName Not In ("WmiPrvSE.exe","AppVClient.exe","svchost.exe","CompatTelRunner.exe")
```

### Application Shimming

Detects application shimming through sdbinst or registry modification.
Reference: keyboardcrunch

```
(SrcProcName = "sdbinst.exe" and ProcessCmd ContainsCIS ".sdb") OR ((RegistryKeyPath ContainsCIS "AppInit_DLLs" OR RegistryPath  ContainsCIS "AppCompatFlags") AND (EventType = "Registry Value Create" OR EventType = "Registry Value Modified"))
```

### Browser Extension Installation

This query takes a lazy approach to detecting the staging of xpi or crx extension packages for installation within Chrome and Firefox based browsers. Unsure how to filter our extension updates without excluding too much.
Reference: keyboardcrunch

```
( FileFullName RegExp "\bWebstore Downloads\b.*\.(crx)$" OR FileFullName RegExp "\bstaged\b.*\.(xpi)$" ) AND EventType = "File Creation" AND NOT tgtFilePath Contains Anycase "sentinelone_visibility"
```

### Change Default File Association

This query takes a lazy approach to detecting the staging of xpi or crx extension packages for installation within Chrome and Firefox based browsers. Unsure how to filter our extension updates without excluding too much.
Reference: keyboardcrunch

```
TgtProcCmdLine ContainsCIS "assoc" and TgtProcCmdLine RegExp ".*=.*"
```

### Local Account Added

In the query below we'll query all instances of local accounts being created for Windows, Linux, and OSX. Depending on your environment, you may find quite a bit of noise with the Linux useradd command.
Reference: keyboardcrunch

```
SrcProcCmdLine In Contains Anycase ("net user /add","useradd","New-LocalUser") OR SrcProcCmdLine RegExp "\bdscl\b.*\b/\create\b" OR SrcProcCmdLine RegExp "\bnet localgroup administrators\b.*\b\/add\b"
```

### Registry Run Keys / Startup Folder

Here we're just focusing on the addition of registry keys to Run, RunOnce, RunOnceEx keys where Parent Process isn't "trusted".
Reference: keyboardcrunch

```
FileFullName ContainsCIS "Programs\Startup" AND FileType In Contains Anycase ("vbs","jse","bat") AND EventType = "File Creation"
```

### Scheduled Tasks

Our goal with this query is to detect any schtasks /create command as well as any use of the New-ScheduledTask* cmdlets from powershell, and to prevent noise from services and updates we'll exclude a list of system "trusted" SrcProcParentName executables.
Needs a good bit to baseline

```
IndicatorName = "ScheduleTaskRegister" AND SrcProcParentName Not In ("Integrator.exe","OfficeClickToRun.exe","services.exe","OneDriveSetup.exe","Ccm32BitLauncher.exe","WmiPrvSE.exe")
```

### Startup Shortcuts

Focuses on Test 2: Detection .lnk or .url files written to Startup folders. Filters noise with SrcProcName Not In (list) but you can remove noise from 3rd party update services updating their links by adding SrcProcParentName != "userinit.exe" to the query.
Needs a good bit to baseline

```
(FileFullName ContainsCIS "Microsoft\Windows\Start Menu\Programs\Startup" AND TgtFileExtension In Contains ("lnk","url") AND EventType = "File Creation") AND SrcProcName Not In ("ONENOTE.EXE","msiexec.exe")
```

### Web Shell

I wanted to get complicated and find any process pulling content from the internet before copying to inetpub but couldn't get that working, so we went generic with our detection and filtered out possibly trusted sources of noise.
Needs a good bit to baseline

```
EventType = "File Creation" AND FileFullName ContainsCIS "inetpub\wwwroot" AND TgtFileExtension In Contains Anycase ("jsp","aspx","php") AND SrcProcName Not In ("explorer.exe","msdeploy.exe")
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
