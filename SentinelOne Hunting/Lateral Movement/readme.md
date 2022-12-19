## Lateral Movement

```
TgtProcCmdLine In Contains Anycase ("sekurlsa::pth","/ntlm:","kerberos::ptt")
OR (CmdLine Contains Anycase "portproxy add")
OR (SrcProcName = "tscon.exe" AND SrcProcCmdLine ContainsCIS "/dest:" AND NOT EndpointName = "GATUCTNUTCCR14W")
OR (TgtProcName = "cmdkey.exe" AND TgtProcCmdLine ContainsCIS "/generic:TERMSRV" AND TgtProcCmdLine ContainsCIS "/user:" AND TgtProcCmdLine ContainsCIS "/pass:")
OR (CmdLine Contains Anycase "process call create" AND NOT (TgtProcCmdLine Contains Anycase "Cloud_DataCollector" OR srcProcCmdLine Contains Anycase "Cloud_DataCollector"))
OR ((TgtProcCmdLine ContainsCIS "GetTypeFromProgID(" AND TgtProcCmdLine ContainsCIS "MMC20.application" AND TgtProcCmdLine ContainsCIS ".Document.ActiveView.ExecuteShellCommand(") OR (TgtProcName = "wmic.exe" AND TgtProcCmdLine ContainsCIS "/node:" AND TgtProcCmdLine ContainsCIS "process call create") OR ((SrcProcName ContainsCIS "psexec.exe" OR SrcProcDisplayName = "Execute processes remotely") AND DstIp Is Not Empty AND NOT srcProcUser In Contains Anycase ("users")))
```
