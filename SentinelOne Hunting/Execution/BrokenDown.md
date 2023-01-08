## Execution

### AT Scheduled Task

Detect interactive process execution scheduled by AT command.
Reference: keyboardcrunch

```
TgtProcName = "at.exe" AND TgtProcCmdLine ContainsCIS "/interactive "
```


### Certutil for C2 or to pull files

Technique used by APT41, but also others

```
ProcessCmd In CONTAINS ("certutil","certutil.exe") AND ProcessCmd In Contains ("url","decode","hashfile")
```

### Downloadstring (not usually normal)

Alot of processes use DownloadFile but not so much Downloadstring

```
ProcessCmd CONTAINS "DownloadString" AND ProcessCmd DOES NOT CONTAIN "chocolatey"
```

### Inhibit System Recovery

Reference: keyboardcrunch

```
TgtProcCmdLine In Contains Anycase ("delete shadows","shadowcopy delete","delete catalog","recoveryenabled no") OR (TgtProcCmdLine ContainsCIS "Win32_ShadowCopy" AND TgtProcCmdLine ContainsCIS "Delete()") OR (SrcProcCmdScript ContainsCIS "Win32_ShadowCopy" AND SrcProcCmdScript ContainsCIS "Delete()")
```

### Kali Common Tools

Reference: https://tdm.socprime.com/tdm/info/q9Q5bNhgATUD/#sigma

```
TgtProcImagePath IN Contains Anycase ("/sqlmap","/teamserver","/aircrack-ng","/john","/setoolkit","/wpscan","/hydra","/nikto")
```

### Powercat Hafnium (targeted vulnerable Exchange servers)

Reference: https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/

```
ProcessCmd CONTAINS anycase "powercat"
```

### Powershell Empire Listeners, Stagers, and Modules invocation

Reference: https://hackmag.com/security/powershell-empire/

```
ProcessCmd In CONTAINS anycase ("uselistener","usestager","usemodule") AND NOT (srcProcName = "EvoMouseListener.exe" OR srcProcCmdLine contains anycase "EvoMouseListener")
```
