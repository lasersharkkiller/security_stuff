## Initial Access

### Certutil Abuse

Reference: 
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil 
- https://www.varonis.com/blog/the-malware-hiding-in-your-windows-system32-folder-part-iii-certutil-and-alternate-data-streams 
-  https://www.trendmicro.com/en_us/research/18/j/malware-targeting-brazil-uses-legitimate-windows-components-wmi-and-certutil-as-part-of-its-routine.html  

```
SrcProcName Contains Anycase "certutil" AND SrcProcCmdLine In Contains Anycase ("urlcache","encode","decode","decodehex")
```

```
SrcProcCmdLine In Contains Anycase ("copy","cp") AND SrcProcCmdLine In Contains Anycase ("certutil") AND NOT SrcProcCmdLine Contains Anycase “DigiCertUtil”
```

### Cover Your Tracks

Reference: https://digi.ninja/blog/hiding_bash_history.php#:~:text=unset%20HISTFILE%20%2D%20Clears%20the%20variable,of%20commands%20to%20not%20log.

```
CmdLine In Contains Anycase ("export HISTSIZE=0","unset histfile","history -c","history -r","export HISTIGNORE") AND NOT CmdLine Contains Anycase "JOBHISTORY -regex"
```

### Double Extension

Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns. Before I was using EndsWith Anycase, but S1 does not support In EndsWith Anycase so I had to switch to In Contains Anycase which makes it less efficient but allows me to use less operators and in the end use less custom star rules (considering they want 140k to do 300 rules).

```
TgtProcImagePath In Contains Anycase (".doc.exe",".docx.exe",".xls.exe",".xlsx.exe",".ppt.exe",".pptx.exe",".rtf.exe",".pdf.exe",".txt.exe","      .exe","______.exe")
```

### Enable Guest account with RDP and Admin

Detects enabling of Guest account, adding Guest account to groups, as well as changing of Deny/Allow of Terminal Server connections through Registry changes.
Reference: keyboardcrunch

```
(SrcProcCmdLine ContainsCIS "net localgroup" AND SrcProcCmdLine ContainsCIS "guest /add") OR (SrcProcCmdLine ContainsCIS "net user" AND SrcProcCmdLine ContainsCIS "/active:yes" AND NOT SrcProcParentName Contains Anycase "pwdspy") OR (RegistryKeyPath In Contains ("Terminal Server\AllowTSConnections","Terminal Server\DenyTSConnections") AND EventType In ("Registry Value Create","Registry Value Modified"))
```

### Microsoft Defender to Download Malware

Reference: https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-can-ironically-be-used-to-download-malware/

```
CmdLine Contains Anycase "MpCmdRun" AND CmdLine Contains Anycase "DownloadFile"
```

### Mshta Abuse

Reference: https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-can-ironically-be-used-to-download-malware/

```
SrcProcName Contains Anycase "mshta" AND SrcProcCmdLine In Contains Anycase (".hta",".vbs",".js")
```

```
TgtProcName Contains Anycase "mshta" AND (SrcProcName In Contains Anycase ("word","excel","powerpoint") OR SrcProcParentName In Contains Anycase ("word","excel","powerpoint"))
```

### Outlook File Type Attacker Techniques

Reference: https://www.darkreading.com/endpoint/post-macro-world-container-files-distribute-malware-replacement
.Ison and .Isom exceptions are last names

```
(SrcProcName Contains Anycase "outlook" AND FilePath In Contains Anycase (".img",".iso",".rar") AND NOT FilePath In Contains Anycase (".Ison",".Isom") AND eventType != "File Deletion")
```

### Outlook Temp Folder Execution

Looks for executions out of the outlook temp folder

```
TgtProcImagePath contains anycase "Temporary Internet Files" AND TgtProcImagePath contains anycase "Content.Outlook"
```

### Outlook Unzip By Command

Reference: https://stackoverflow.com/questions/17546016/how-can-you-zip-or-unzip-from-the-script-using-only-windows-built-in-capabiliti 

```
SrcProcName Contains Anycase "outlook" AND CmdLine In Contains Anycase ("powershell","IO.Compression.ZipFile","jar","Expand-Archive","7zip","tar",".vbs","gzipjs","compact") AND CmdLine In Contains Anycase (".zip",".7z",".rar",".iso",".img",".gz")
```

### PowerShell Spawned From Outlook

Reference: https://www.trendmicro.com/en_us/research/17/e/rising-trend-attackers-using-lnk-files-download-malware.html 


```
TgtProcName Contains Anycase "powershell" AND (SrcProcName In Contains Anycase ("word","excel","powerpoint") OR SrcProcParentName In Contains Anycase ("word","excel","powerpoint")) AND NOT TgtProcCmdLine In Contains Anycase ("NoProfile","ConfigMgrClientHealth.ps1","GetAdobeEntitlement","PSVersionTable","Get-AppxPackage","169.254.169.254")
```

### Registry Trust Record Modification

Alerts on trust record modification within the registry, indicating usage of macros

```
RegistryKeyPath contains anycase "TrustRecords"
```

### Remote Desktop User Add

Detects suspicious command line in which a user gets added to the local Remote Desktop Users group.

```
(SrcProcCmdLine ContainsCIS "net localgroup" AND SrcProcCmdLine ContainsCIS "guest /add") OR (SrcProcCmdLine ContainsCIS "net user" AND SrcProcCmdLine ContainsCIS "/active:yes" AND NOT SrcProcParentName Contains Anycase "pwdspy") OR (RegistryKeyPath In Contains ("Terminal Server\AllowTSConnections","Terminal Server\DenyTSConnections") AND EventType In ("Registry Value Create","Registry Value Modified"))
```

### Stop-Process (Used by Log4Shell)

Reference: https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-203a
Log4Shell uses Stop-Process in it's Initial actions which only has a couple false positives that I see, so it could be an indicator. It's possible other malware might use this for things such as disabling antivirus or other services that might detect it.


```
CmdLine Contains Anycase "Stop-Process" AND NOT CmdLine In Contains Anycase ("Stop-Processing","lpwinmetro")
```

### Windows Event Log Clearing

Reference: https://attack.mitre.org/techniques/T1070/001/

```
CmdLine In Contains Anycase ("wevtutil cl")
```
