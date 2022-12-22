## Initial Access

```
CmdLine Contains Anycase "export HISTSIZE=0"
OR ((TgtProcImagePath endswith ".doc.exe" OR TgtProcImagePath endswith ".docx.exe" OR TgtProcImagePath endswith ".xls.exe" OR TgtProcImagePath endswith ".xlsx.exe" OR TgtProcImagePath endswith ".ppt.exe" OR TgtProcImagePath endswith ".pptx.exe" OR TgtProcImagePath endswith ".rtf.exe" OR TgtProcImagePath endswith ".pdf.exe" OR TgtProcImagePath endswith ".txt.exe" OR TgtProcImagePath endswith "      .exe" OR TgtProcImagePath endswith "______.exe"))
OR ((SrcProcCmdLine ContainsCIS "net localgroup" AND SrcProcCmdLine ContainsCIS "guest /add") OR (SrcProcCmdLine ContainsCIS "net user" AND SrcProcCmdLine ContainsCIS "/active:yes" AND NOT SrcProcParentName Contains Anycase "pwdspy") OR (RegistryKeyPath In Contains ("Terminal Server\AllowTSConnections","Terminal Server\DenyTSConnections") AND EventType In ("Registry Value Create","Registry Value Modified")))
```
