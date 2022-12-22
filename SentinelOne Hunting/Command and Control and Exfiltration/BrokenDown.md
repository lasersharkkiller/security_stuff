## Command and Control

### Certutil for C2 or to pull files

Technique used by APT41, but also others

```
ProcessCmd In CONTAINS ("certutil","certutil.exe") AND ProcessCmd In Contains ("url","decode","hashfile")
```

### Echo with Obfuscation 

Can be used in various manners but one example: https://www.bleepingcomputer.com/news/security/winnti-hackers-split-cobalt-strike-into-154-pieces-to-evade-detection/

```
ProcessCmd CONTAINS anycase "echo" AND ProcessCmd In Contains Anycase ("AAAAAAAA")
```

### Invoke-WebRequest Powershell data POST and PUT 

Reference: keyboardcrunch

```
SrcProcCmdLine ContainsCIS "Invoke-WebRequest" AND (SrcProcCmdLine ContainsCIS "-Method Put" OR SrcProcCmdLine ContainsCIS "-Method Post") and NOT srcProcCmdLine contains "slackb.com"
```

### O365 New-PSDrive

Reference: https://www.blackhat.com/docs/us-17/wednesday/us-17-Dods-Infecting-The-Enterprise-Abusing-Office365-Powershell-For-Covert-C2.pdf

```
ProcessCmd CONTAINS "New-PSDrive"
```

### PowerShell Encoding

Tons of attackers use powershell encoding to obfuscate

```
CmdLine In Contains Anycase ("powershell -e","frombase64string") AND NOT CmdLine In Contains Anycase ("executionpolicy","SentinelTroubleshooter.ps1")
```

### TOR DNS ending with .onion

```
DNS EndsWith ".onion"
```

### Resmoncfg Configuration File Used By Malware

Reference: CISA Malware Analysis Report 10412261. The malware loads the configuration file
"C:\ProgramData\setprofile.resmoncfg" if installed on the compromised system. The malware terminates its code execution if the
configuration is not installed on the compromised system.

```
TgtFileExtension Contains Anycase "resmoncfg" AND EventType = "File Creation"  AND SrcProcName != "CLRestore.exe"
```

### wget -t

Reference CISA #10413062; The dll uses wget -t 1 to limit attempts to download only once, oddly wget -t never triggers in a 90 day baseline

```
CmdLine Contains Anycase "wget -t"
```
