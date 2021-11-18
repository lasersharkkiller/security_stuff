## SPAN port setup
Interface / Assignments (We need to activate the other phyical ports)  
Add a new physical port (probably names it OPT1)  
Interfaces / OPT1 / Enable / Save / Apply  
Interfaces / Assignments / Bridges / Add / Select WAN+LAN / Advanced / Span Port = OPT1 / Save (sends SPAN port out OPT1)  

Attach physical cabling from pfsense to sensor  

OR set up a physical tap  

Check on the sensor:  
sudo yum install tcpdump  
sudo tcpdump -i interface  

Change settings for port on sensor:  
sudo vi /etc/sysconfig/network-scripts/ifcfg-enp5s0 (monitor interface)  
BOOTPROTO=none  
ONBOOT=yes  
NM_CONTROLLED=no  
