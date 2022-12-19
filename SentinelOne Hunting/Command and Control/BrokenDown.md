## Command and Control

### PowerShell Encoding

Tons of attackers use powershell encoding to obfuscate

```
ProcessCmd CONTAINS "powershell -e" AND ProcessCmd Does Not Contain "executionpolicy" AND CmdLine Does Not Contain "SentinelTroubleshooter.ps1"
```

### Use of certutil for C2 or to pull files

Technique used by APT41, but also others

```
ProcessCmd In CONTAINS ("certutil","certutil.exe") AND ProcessCmd In Contains ("url","decode","hashfile")
```
