## Persistence

```
FilePath Contains Anycase "C:\Windows\AppData\Roaming\Appnet" and FilePath Contains Anycase ".exe"
OR ((RegistryKeyPath ContainsCIS "CurrentVersion\Image File Execution Options" AND RegistryKeyPath ContainsCIS ".exe\Debugger") AND (EventType = "Registry Value Create" OR EventType = "Registry Key Create"))
```
