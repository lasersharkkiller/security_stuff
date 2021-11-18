## About
Stenographer is a packet capture tool ; Files - Index & frame  < Docket  
Steno type written in C, the other written in Go.  
Config: /etc/Stenographer/config  
Docket config: /etc/Docket/something  
Config override files: /etc/sysconfig/service name  

## Configure
sudo yum install stenographer  
cd /etc/stenographer  
sudo vi config  
PacketsDirectory: "/data/stenographer/packets/" (we set up /data as separate partition)  
IndexDirectory: "/data/stenographer/index"  
Interface: "enp5s0" (applicable monitor interface)  
Host: dont need to change in our case but can query multiple; docket looks at various stenographers but you could do here  
*for DiskFreePercentage consider packet flow; keep in mind cleans up every 5 minutes so if you have high throughput and not much storage might need to change it  

sudo systemctl start stenographer :doesn't work  
journalctl -xeu stenographer :start at bottom and work your way up; instructor always starts w/journalctl, and troubleshoot starts w/permissions  
^start^status :troubleshoot - saw didnt have proper permissions  
sudo systemctl status stenographer -l :alt troubleshoot  
looking at permissions on stenographer its owned by root, we changed the owner to stenographer account:  
cd .. (/etc/ dir)  
sudo chown -R stenographer: stenographer/ :R is recursive  
cd /data/  
sudo chown -R stenographer: stenographer/ :R is recursive  
ls -la to check  

But one more issue (firewall)  
sudo firewall-cmd --add-port=1234/tcp --permanent  
sudo firewall-cmd --reload  
sudo firewall-cmd --list/--list-all-zones :view firewall rules  

## Certs
which stenokeys / which stenoread :similar to locate  
sudo stenokeys.sh stenographer stenographer  
cd /etc/stenographer/certs/ ; ls -l :see newly created certs  

sudo systemctl start stenographer  
^start^status :even though it shows one failure (from before) it's good  
sudo systemctl enable stenographer  

Test:  
ping 8.8.8.8  
sudo stenoread 'host 8.8.8.8'  
