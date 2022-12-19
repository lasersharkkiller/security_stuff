## Lateral Movement

```
TgtProcCmdLine In Contains Anycase ("sekurlsa::pth","/ntlm:","kerberos::ptt")
OR (CmdLine Contains Anycase "portproxy add")
OR (CmdLine Contains Anycase "process call create" AND NOT (TgtProcCmdLine Contains Anycase "Cloud_DataCollector" OR srcProcCmdLine Contains Anycase "Cloud_DataCollector"))
```
