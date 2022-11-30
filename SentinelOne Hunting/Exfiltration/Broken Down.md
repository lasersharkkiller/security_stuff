## Exfiltration

### Detection of powershell data POST and PUT with Invoke-WebRequest. 

I had to build slack into the baseline for this.

```
SrcProcCmdLine ContainsCIS "Invoke-WebRequest" AND (SrcProcCmdLine ContainsCIS "-Method Put" OR SrcProcCmdLine ContainsCIS "-Method Post") and NOT srcProcCmdLine contains "slackb.com"
```
