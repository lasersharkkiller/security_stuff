## Execution

### Use of certutil for C2 or to pull files

Technique used by APT41, but also others

```
ProcessCmd In CONTAINS ("certutil","certutil.exe") AND ProcessCmd In Contains ("url","decode","hashfile")
```

### Looks for signs of Hafnium Powercat (targeted vulnerable Exchange servers)

Reference: https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/

```
ProcessCmd CONTAINS anycase "powercat"
```

### Powershell Empire Listeners, Stagers, and Modules invocation

Reference: https://hackmag.com/security/powershell-empire/

```
ProcessCmd In CONTAINS anycase ("uselistener","usestager","usemodule") AND NOT (srcProcName = "EvoMouseListener.exe" OR srcProcCmdLine contains anycase "EvoMouseListener")
```
