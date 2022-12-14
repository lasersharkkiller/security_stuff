## Persistence

### Detect exe's added to AppData\Roaming\Appnet

Technique came from analyzing Cybersecurity and Infrastructure Security Agency report 10412261.r2.v1

```
FilePath Contains Anycase "C:\Windows\AppData\Roaming\Appnet" and FilePath Contains Anycase ".exe"
```


### Accessibility Features

Detections addition of a debugger process to executables using Image File Execution Options.
Reference: keyboardcrunch

```
(RegistryKeyPath ContainsCIS "CurrentVersion\Image File Execution Options" AND RegistryKeyPath ContainsCIS ".exe\Debugger") AND (EventType = "Registry Value Create" OR EventType = "Registry Key Create")
```
