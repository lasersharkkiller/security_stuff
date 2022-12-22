## Tools

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
