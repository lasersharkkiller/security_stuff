## Execution

```
(ProcessCmd In CONTAINS ("certutil","certutil.exe") AND ProcessCmd In Contains ("url","decode","hashfile"))
OR (ProcessCmd CONTAINS "DownloadString" AND ProcessCmd DOES NOT CONTAIN "chocolatey")
OR (TgtProcCmdLine In Contains Anycase ("delete shadows","shadowcopy delete","delete catalog","recoveryenabled no") OR (TgtProcCmdLine ContainsCIS "Win32_ShadowCopy" AND TgtProcCmdLine ContainsCIS "Delete()") OR (SrcProcCmdScript ContainsCIS "Win32_ShadowCopy" AND SrcProcCmdScript ContainsCIS "Delete()"))
OR (ProcessCmd CONTAINS anycase "powercat")
OR (ProcessCmd In CONTAINS anycase ("uselistener","usestager","usemodule") AND NOT (srcProcName = "EvoMouseListener.exe" OR srcProcCmdLine contains anycase "EvoMouseListener"))
```
