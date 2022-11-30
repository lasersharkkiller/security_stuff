## Privilege Escalation

### Detect interactive process execution scheduled by AT command.

```
TgtProcName = "at.exe" AND TgtProcCmdLine ContainsCIS "/interactive "
```

