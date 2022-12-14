## Command and Control

### Commands to Stop Windows Defender

Technique came from analyzing Cybersecurity and Infrastructure Security Agency report 10412261.r2.v1

```
ProcessCmd CONTAINS "powershell -e" AND ProcessCmd Does Not Contain "executionpolicy" AND CmdLine Does Not Contain "SentinelTroubleshooter.ps1"
```
