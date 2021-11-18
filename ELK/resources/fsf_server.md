```python
#!/usr/bin/env python
#
# Basic configuration attributes for scanner. Used as default
# unless the user overrides them.
#

SCANNER_CONFIG = { 'LOG_PATH' : '/data/fsf/logs',
                   'YARA_PATH' : '/var/lib/yara-rules/rules.yara',
                   'EXPORT_PATH' : '/data/fsf/archive',
                   'TIMEOUT' : 60,
                   'PID_PATH': '/run/fsf/fsf.pid',
                   'MAX_DEPTH' : 10,
                   'ACTIVE_LOGGING_MODULES': ['rockout', 'scan_log'] }

SERVER_CONFIG = { 'IP_ADDRESS' : "localhost",
                  'PORT' : 5800 }
```
