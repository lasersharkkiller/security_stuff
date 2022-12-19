## Lateral Movement

```
TgtProcCmdLine In Contains Anycase ("sekurlsa::pth","/ntlm:","kerberos::ptt")
OR (CmdLine Contains Anycase "portproxy add")
OR (SrcProcName = "tscon.exe" AND SrcProcCmdLine ContainsCIS "/dest:" AND NOT EndpointName = "GATUCTNUTCCR14W")
OR (TgtProcName = "cmdkey.exe" AND TgtProcCmdLine ContainsCIS "/generic:TERMSRV" AND TgtProcCmdLine ContainsCIS "/user:" AND TgtProcCmdLine ContainsCIS "/pass:")
OR (CmdLine Contains Anycase "process call create" AND NOT (TgtProcCmdLine Contains Anycase "Cloud_DataCollector" OR srcProcCmdLine Contains Anycase "Cloud_DataCollector"))
```
