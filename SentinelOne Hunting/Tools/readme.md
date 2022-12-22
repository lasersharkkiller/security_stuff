## Tools

```
((TgtProcImagePath endswith "\w3wp.exe" OR SrcProcImagePath endswith "\w3wp.exe") AND (TgtProcCmdLine contains anycase "&ipconfig&echo" OR TgtProcCmdLine contains anycase "&quser&echo" OR TgtProcCmdLine contains anycase "&whoami&echo" OR TgtProcCmdLine contains anycase "&c:&echo" OR TgtProcCmdLine contains anycase "&cd&echo" OR TgtProcCmdLine contains anycase "&dir&echo" OR TgtProcCmdLine contains anycase "&echo [E]" OR TgtProcCmdLine contains anycase "&echo [S]"))
OR (((TgtProcCmdLine contains anycase "appcmd.exe add module" AND SrcProcImagePath endswith "\w3wp.exe") OR (TgtProcCmdLine contains anycase " system.enterpriseservices.internal.publish" AND SrcProcImagePath endswith "\w3wp.exe" AND TgtProcImagePath endswith "\powershell.exe") OR (TgtProcCmdLine contains anycase " \\gacutil.exe /I" AND SrcProcImagePath endswith "\w3wp.exe")))
OR (TgtProcCmdLine contains anycase "-exec bypass -w 1 -enc")
OR (TgtProcCmdLine contains anycase " runassystem ")
```
