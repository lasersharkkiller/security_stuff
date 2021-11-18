## About
IDS, outputs even.json. Filebeat reads the eve.json  
Config file: /etc/suricata/suricata.yaml  
Config override files: /etc/sysconfig/service name  

## Config
```
sudo yum install suricata  
cd /etc/suricata
sudo vi include-suricata.yaml
i; paste file from class resources
```

```
sudo vi suricata.yaml  
:set nu - sets #s  
shift+G in command mode goes to bottom  
include: includes other files to add  
i insert mode; remove # and change filename  
add the include-suricata.yaml from class resources?  
```

Set monitor interface for suricata  
```
cd /etc/sysconfig :this is the LAST override file, even user defined override files  
sudo vi suricata  
change -i to OPTIONS="--af-packet=enp5s0 --user suricata "  
```

Get Suricata to point at NUC instead of internet to update:  
```
sudo suricata-update add-source local-emerging-threats http://192.168.2.20/share/emerging.rules.tar.gz  
sudo suricata-update :in our case we have to add %YAML 1.1 to our .yaml file  
```

Set ownership:  
```
cd /data/  
sudo chown -R suricata: suricata/  
```

Pin core to service
```
cat /proc/cpuinfo | grep -E 'processor|physical id|core id' | xargs-l3  
*shows cores (i.e. 16), physical processor (i.e. 2), core id. If hyperthreading is enabled it would have not have shown all 16 cores  
--NEVER pin core ids 0 because OS defaults to core id 0--  
```

Start Suricata
```
sudo systemctl start suricata  
sudo systemctl status suricata -l  
sudo systemctl enable suricata  
journalctl -xeu suricata :start at bottom and work your way up; instructor always starts w/journalctl, and troubleshoot starts w/permissions  
```
