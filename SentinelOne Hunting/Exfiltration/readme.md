## Exfiltration

There are a number of ways to use current supported indicators to detect data exfiltration, some with higher accuracy than others. Detection by command lines can have environmental noise, detection based on network connection indicators may require lost of custom filtering as well.

```
SrcProcCmdLine ContainsCIS "Invoke-WebRequest" AND (SrcProcCmdLine ContainsCIS "-Method Put" OR SrcProcCmdLine ContainsCIS "-Method Post") and NOT srcProcCmdLine contains "slackb.com"
```
