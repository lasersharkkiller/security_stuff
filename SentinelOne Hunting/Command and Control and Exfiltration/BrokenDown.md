## Command and Control

### PowerShell Encoding

Tons of attackers use powershell encoding to obfuscate

```
ProcessCmd CONTAINS "powershell -e" AND NOT  ProcessCmd In Contains ("executionpolicy","SentinelTroubleshooter.ps1")
```

### Look for obfuscation with the echo command 

Can be used in various manners but one example: https://www.bleepingcomputer.com/news/security/winnti-hackers-split-cobalt-strike-into-154-pieces-to-evade-detection/

```
ProcessCmd CONTAINS anycase "echo" AND ProcessCmd In Contains Anycase ("AAAAAAAA")
```

### Detection of powershell data POST and PUT with Invoke-WebRequest. 

Reference: keyboardcrunch

```
SrcProcCmdLine ContainsCIS "Invoke-WebRequest" AND (SrcProcCmdLine ContainsCIS "-Method Put" OR SrcProcCmdLine ContainsCIS "-Method Post") and NOT srcProcCmdLine contains "slackb.com"
```

### Use of certutil for C2 or to pull files

Technique used by APT41, but also others

```
ProcessCmd In CONTAINS ("certutil","certutil.exe") AND ProcessCmd In Contains ("url","decode","hashfile")
```

### O365 New-PSDrive

Reference: https://www.blackhat.com/docs/us-17/wednesday/us-17-Dods-Infecting-The-Enterprise-Abusing-Office365-Powershell-For-Covert-C2.pdf

```
ProcessCmd CONTAINS "New-PSDrive"
```
