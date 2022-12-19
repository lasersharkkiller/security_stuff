## Command and Control and Exfiltration

```
ProcessCmd CONTAINS "powershell -e" AND ProcessCmd Does Not Contain "executionpolicy" AND CmdLine Does Not Contain "SentinelTroubleshooter.ps1"
OR (ProcessCmd CONTAINS anycase "echo" AND ProcessCmd In Contains Anycase ("AAAAAAAA"))
OR (SrcProcCmdLine ContainsCIS "Invoke-WebRequest" AND (SrcProcCmdLine ContainsCIS "-Method Put" OR SrcProcCmdLine ContainsCIS "-Method Post") and NOT srcProcCmdLine contains "slackb.com")
OR (ProcessCmd In CONTAINS ("certutil","certutil.exe") AND ProcessCmd In Contains ("url","decode","hashfile"))
```
