## Initial Access

### Hunt Pack #1
```
(CmdLine In Contains Anycase ("export HISTSIZE=0","unset histfile","history -c","history -r","export HISTIGNORE") AND NOT CmdLine Contains Anycase "JOBHISTORY -regex")
OR TgtProcImagePath In Contains Anycase (".doc.exe",".docx.exe",".xls.exe",".xlsx.exe",".ppt.exe",".pptx.exe",".rtf.exe",".pdf.exe",".txt.exe","      .exe","______.exe")
OR ((SrcProcCmdLine ContainsCIS "net localgroup" AND SrcProcCmdLine ContainsCIS "guest /add") OR (SrcProcCmdLine ContainsCIS "net user" AND SrcProcCmdLine ContainsCIS "/active:yes" AND NOT SrcProcParentName Contains Anycase "pwdspy") OR (RegistryKeyPath In Contains ("Terminal Server\AllowTSConnections","Terminal Server\DenyTSConnections") AND EventType In ("Registry Value Create","Registry Value Modified")))
OR (TgtProcImagePath contains anycase "Temporary Internet Files" AND TgtProcImagePath contains anycase "Content.Outlook")
OR RegistryKeyPath Contains Anycase "TrustRecords"
OR ((SrcProcCmdLine ContainsCIS "net localgroup" AND SrcProcCmdLine ContainsCIS "guest /add") OR (SrcProcCmdLine ContainsCIS "net user" AND SrcProcCmdLine ContainsCIS "/active:yes" AND NOT SrcProcParentName Contains Anycase "pwdspy") OR (RegistryKeyPath In Contains ("Terminal Server\AllowTSConnections","Terminal Server\DenyTSConnections") AND EventType In ("Registry Value Create","Registry Value Modified")))
```

### Hunt Pack #2:

```
CmdLine In Contains Anycase ("wevtutil cl")
```
