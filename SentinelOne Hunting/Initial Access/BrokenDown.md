## Initial Access

### Cover Your Tracks

This one will be built out a bit

```
CmdLine Contains Anycase "export HISTSIZE=0"
```

### Double Extension

Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns.

```
(TgtProcImagePath endswith ".doc.exe" OR TgtProcImagePath endswith ".docx.exe" OR TgtProcImagePath endswith ".xls.exe" OR TgtProcImagePath endswith ".xlsx.exe" OR TgtProcImagePath endswith ".ppt.exe" OR TgtProcImagePath endswith ".pptx.exe" OR TgtProcImagePath endswith ".rtf.exe" OR TgtProcImagePath endswith ".pdf.exe" OR TgtProcImagePath endswith ".txt.exe" OR TgtProcImagePath endswith "      .exe" OR TgtProcImagePath endswith "______.exe")
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
