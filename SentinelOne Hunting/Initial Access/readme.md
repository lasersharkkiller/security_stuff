## Initial Access

*Remember these are limited to 20 operators so that you can plug them into Custom Star Rules, formerly known as Watchlist.

### Hunt Pack #1
```
(SrcProcName Contains Anycase "certutil" AND SrcProcCmdLine In Contains Anycase ("urlcache","encode","decode","decodehex"))
OR (SrcProcCmdLine In Contains Anycase ("copy","cp") AND SrcProcCmdLine In Contains Anycase ("certutil") AND NOT SrcProcCmdLine Contains Anycase "“DigiCertUtil")
OR (CmdLine In Contains Anycase ("export HISTSIZE=0","unset histfile","history -c","history -r","export HISTIGNORE") AND NOT CmdLine Contains Anycase "JOBHISTORY -regex")
OR TgtProcImagePath In Contains Anycase (".doc.exe",".docx.exe",".xls.exe",".xlsx.exe",".ppt.exe",".pptx.exe",".rtf.exe",".pdf.exe",".txt.exe","      .exe","______.exe")
OR ((SrcProcCmdLine ContainsCIS "net localgroup" AND SrcProcCmdLine ContainsCIS "guest /add") OR (SrcProcCmdLine ContainsCIS "net user" AND SrcProcCmdLine ContainsCIS "/active:yes" AND NOT SrcProcParentName Contains Anycase "pwdspy") OR (RegistryKeyPath In Contains ("Terminal Server\AllowTSConnections","Terminal Server\DenyTSConnections") AND EventType In ("Registry Value Create","Registry Value Modified")))
OR (CmdLine Contains Anycase "MpCmdRun" AND CmdLine Contains Anycase "DownloadFile")
OR (SrcProcName Contains Anycase "mshta" AND SrcProcCmdLine In Contains Anycase (".hta",".vbs",".js"))
```

### Hunt Pack #2:

```
(TgtProcName Contains Anycase "mshta" AND (SrcProcName In Contains Anycase ("word","excel","powerpoint") OR SrcProcParentName In Contains Anycase ("word","excel","powerpoint")))
OR (SrcProcName Contains Anycase "outlook" AND FilePath In Contains Anycase (".img",".iso",".rar") AND NOT FilePath In Contains Anycase (".Ison",".Isom") AND eventType != "File Deletion")
OR (TgtProcImagePath Contains Anycase "Temporary Internet Files" AND TgtProcImagePath Contains Anycase "Content.Outlook")
OR (SrcProcName Contains Anycase "outlook" AND CmdLine In Contains Anycase ("powershell","IO.Compression.ZipFile","jar","Expand-Archive","7zip","tar",".vbs","gzipjs","compact") AND CmdLine In Contains Anycase (".zip",".7z",".rar",".iso",".img",".gz"))
OR (TgtProcName Contains Anycase "powershell" AND (SrcProcName In Contains Anycase ("word","excel","powerpoint") OR SrcProcParentName In Contains Anycase ("word","excel","powerpoint")) AND NOT TgtProcCmdLine In Contains Anycase ("NoProfile","ConfigMgrClientHealth.ps1","GetAdobeEntitlement","PSVersionTable","Get-AppxPackage","169.254.169.254"))
OR RegistryKeyPath Contains Anycase "TrustRecords"
```

### Hunt Pack #3:

```
(SrcProcCmdLine ContainsCIS "net localgroup" AND SrcProcCmdLine ContainsCIS "guest /add") OR (SrcProcCmdLine ContainsCIS "net user" AND SrcProcCmdLine ContainsCIS "/active:yes" AND NOT SrcProcParentName Contains Anycase "pwdspy") OR (RegistryKeyPath In Contains ("Terminal Server\AllowTSConnections","Terminal Server\DenyTSConnections") AND EventType In ("Registry Value Create","Registry Value Modified"))
OR CmdLine Contains Anycase "Stop-Process" AND NOT CmdLine In Contains Anycase ("Stop-Processing","lpwinmetro")
OR CmdLine In Contains Anycase ("wevtutil cl")
```
