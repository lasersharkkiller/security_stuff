## Lateral Movement

### Pass the Hash & Pass the TIcket

Reference: keyboardcrunch

```
TgtProcCmdLine In Contains Anycase ("sekurlsa::pth","/ntlm:","kerberos::ptt")
```

### Port Proxy

Reference: https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding also SEC588 b5p97

```
CmdLine Contains Anycase "portproxy add"
```

### WMI Remote Code Execution

Baselined out IBM Data Collector

```
CmdLine Contains Anycase "process call create" AND NOT (TgtProcCmdLine Contains Anycase "Cloud_DataCollector" OR srcProcCmdLine Contains Anycase "Cloud_DataCollector")
```
