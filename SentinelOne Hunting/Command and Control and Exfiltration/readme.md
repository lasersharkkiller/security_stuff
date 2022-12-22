## Command and Control and Exfiltration

```
ProcessCmd In CONTAINS ("certutil","certutil.exe") AND ProcessCmd In Contains ("url","decode","hashfile")
OR ((((TgtProcImagePath endswith "\curl.exe" OR TgtProcImagePath endswith "\wget.exe") OR (TgtProcCmdLine contains anycase "Invoke-WebRequest" OR TgtProcCmdLine contains anycase "iwr " OR TgtProcCmdLine contains anycase "curl " OR TgtProcCmdLine contains anycase "wget " OR TgtProcCmdLine contains anycase "Start-BitsTransfer" OR TgtProcCmdLine contains anycase ".DownloadFile(" OR TgtProcCmdLine contains anycase ".DownloadString(")) AND (TgtProcCmdLine contains anycase "https://attachment.outlook.live.net/owa/" OR TgtProcCmdLine contains anycase "https://onenoteonlinesync.onenote.com/onenoteonlinesync/")))
OR (ProcessCmd CONTAINS anycase "echo" AND ProcessCmd In Contains Anycase ("AAAAAAAA"))
OR (SrcProcCmdLine ContainsCIS "Invoke-WebRequest" AND (SrcProcCmdLine ContainsCIS "-Method Put" OR SrcProcCmdLine ContainsCIS "-Method Post") and NOT srcProcCmdLine contains "slackb.com")
OR (ProcessCmd CONTAINS "New-PSDrive")
OR (CmdLine In Contains Anycase ("powershell -e","frombase64string") AND NOT CmdLine In Contains Anycase ("executionpolicy","SentinelTroubleshooter.ps1"))
OR (DNS EndsWith ".onion")
OR (TgtFileExtension Contains Anycase "resmoncfg" AND EventType = "File Creation"  AND SrcProcName != "CLRestore.exe")
OR (CmdLine Contains Anycase "wget -t")
```
