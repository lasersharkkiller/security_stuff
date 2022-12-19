## Command and Control

```
ProcessCmd CONTAINS "powershell -e" AND ProcessCmd Does Not Contain "executionpolicy" AND CmdLine Does Not Contain "SentinelTroubleshooter.ps1"
OR (ProcessCmd In CONTAINS ("certutil","certutil.exe") AND ProcessCmd In Contains ("url","decode","hashfile"))
```
