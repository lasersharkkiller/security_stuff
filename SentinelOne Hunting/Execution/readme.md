## Execution

```
ProcessCmd In CONTAINS ("certutil","certutil.exe") AND ProcessCmd In Contains ("url","decode","hashfile")
OR (ProcessCmd CONTAINS anycase "powercat")
OR (ProcessCmd In CONTAINS anycase ("uselistener","usestager","usemodule") AND NOT (srcProcName = "EvoMouseListener.exe" OR srcProcCmdLine contains anycase "EvoMouseListener"))
```
