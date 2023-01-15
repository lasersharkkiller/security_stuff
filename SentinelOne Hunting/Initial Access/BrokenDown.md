## Initial Access

### Cover Your Tracks

Reference: https://digi.ninja/blog/hiding_bash_history.php#:~:text=unset%20HISTFILE%20%2D%20Clears%20the%20variable,of%20commands%20to%20not%20log.

```
CmdLine In Contains Anycase ("export HISTSIZE=0","unset histfile","history -c","history -r","export HISTIGNORE") AND NOT CmdLine Contains Anycase "JOBHISTORY -regex"
```

### Double Extension

Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns. Before I was using EndsWith Anycase, but S1 does not support In EndsWith Anycase so I had to switch to In Contains Anycase which makes it less efficient but allows me to use less operators and in the end use less custom star rules (considering they want 140k to do 300 rules).

```
(TgtProcImagePath In Contains Anycase (".doc.exe",".docx.exe",".xls.exe",".xlsx.exe",".ppt.exe",".pptx.exe",".rtf.exe",".pdf.exe",".txt.exe","      .exe","______.exe"))
```

### Enable Guest account with RDP and Admin

Detects enabling of Guest account, adding Guest account to groups, as well as changing of Deny/Allow of Terminal Server connections through Registry changes.
Reference: keyboardcrunch

```
(SrcProcCmdLine ContainsCIS "net localgroup" AND SrcProcCmdLine ContainsCIS "guest /add") OR (SrcProcCmdLine ContainsCIS "net user" AND SrcProcCmdLine ContainsCIS "/active:yes" AND NOT SrcProcParentName Contains Anycase "pwdspy") OR (RegistryKeyPath In Contains ("Terminal Server\AllowTSConnections","Terminal Server\DenyTSConnections") AND EventType In ("Registry Value Create","Registry Value Modified"))
```

### Outlook Temp Folder Execution

Looks for executions out of the outlook temp folder

```
TgtProcImagePath contains anycase "Temporary Internet Files" AND TgtProcImagePath contains anycase "Content.Outlook"
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

### Windows Event Log Clearing

Reference: https://attack.mitre.org/techniques/T1070/001/

```
CmdLine In Contains Anycase ("wevtutil cl")
```
