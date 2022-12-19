## Command and Control

### PowerShell Encoding

Tons of attackers use powershell encoding to obfuscate

```
ProcessCmd CONTAINS "powershell -e" AND ProcessCmd Does Not Contain "executionpolicy" AND CmdLine Does Not Contain "SentinelTroubleshooter.ps1"
```
