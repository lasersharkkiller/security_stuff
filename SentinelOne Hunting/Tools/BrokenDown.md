## Tools

### China Chopper Webshell Process Pattern

Detects patterns found in process executions cause by China Chopper like tiny (ASPX) webshells
Reference: Florian Roth

```
((TgtProcImagePath endswith "\w3wp.exe" OR SrcProcImagePath endswith "\w3wp.exe") AND (TgtProcCmdLine contains anycase "&ipconfig&echo" OR TgtProcCmdLine contains anycase "&quser&echo" OR TgtProcCmdLine contains anycase "&whoami&echo" OR TgtProcCmdLine contains anycase "&c:&echo" OR TgtProcCmdLine contains anycase "&cd&echo" OR TgtProcCmdLine contains anycase "&dir&echo" OR TgtProcCmdLine contains anycase "&echo [E]" OR TgtProcCmdLine contains anycase "&echo [S]"))
```

### IIS Suspicious Module Registration

Detects a suspicious IIS module registration as described in Microsoft threat report on IIS backdoors
Reference: Florian Roth

```
((TgtProcCmdLine contains anycase "appcmd.exe add module" AND SrcProcImagePath endswith "\w3wp.exe") OR (TgtProcCmdLine contains anycase " system.enterpriseservices.internal.publish" AND SrcProcImagePath endswith "\w3wp.exe" AND TgtProcImagePath endswith "\powershell.exe") OR (TgtProcCmdLine contains anycase " \\gacutil.exe /I" AND SrcProcImagePath endswith "\w3wp.exe"))
```

### Mercury Command Line Patterns

Detects suspicious command line patterns as seen being used by MERCURY threat actor
Reference: Florian Roth

```
TgtProcCmdLine contains anycase "-exec bypass -w 1 -enc"
```

### NIRCmd Tool Execution As Local System

Detects the use of NirCmd tool for command execution as SYSTEM user
Reference: Florian Roth

```
TgtProcCmdLine contains anycase " runassystem "
```
