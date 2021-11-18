##Order
1. CentOS
1. stenographer, zeek, suricata
1. zookeeper, kafka
1. Filebeat
1. elasticsearch, kibana
1. logstash

## CentOS setup
Change Date & Time to UTC  
Disable KDump  

Installation Destination: Select both drives. I will configure partitioning. Done. "-" to delete. Click here to create automatically. Security policy off (or messes with some RockNSM settings)  
| Mount Point | Volume Group | Desired Capacity |
| --- | --- | --- |
| /tmp | vg_os | 5 GiB |
| /var | vg_os | 50 GiB  |
| /var/log | vg_os | 50 GiB  |
| /var/log/audit | vg_os | 50 GiB  |
| /var/tmp | vg_os | 10 GiB  |
| /home | vg_os | 50 GiB  |
| swap | vg_os | half of RAM |
| / | vg_os | blank (233 GiB) |
| /data/stenographer | vg_data | 500 GiB  |
| /data/suricata | vg_data | 25 GiB  |
| /data/kafka | vg_data | 100 GiB  |
| /data/zeek | vg_data | 25 GiB  |
| /data/fsf | vg_data | 10 GiB  |
| /data/elasticsearch | vg_data | blank (271 GiB) |

Set root password, and set up admin (remember to check make user admin)  

## Set up static interface
sudo nmtui  
edit connection  
Select 1st one as management interface  
Show / Set config  
Disable (Ignore) IPv6 or Zookeeper / Kafka has issues  
Automatically connect (spacebar to check)

or  

sudo vi /etc/sysconfig/network-scripts/ifcfg-eno1 (eno1 being the monitor int)  
BOOTPROTO=dhcp/static  
delete all IPv6 lines (dd destroys lines)  
ONBOOT=yes (i is insert mode/escape)  
:wq (write and quit)  
:w!  

## Disable ipv6 in sysctl.conf
cd ../..
sudo vi /etc/sysctl.conf  
"o" puts you in insert mode and starts a new line  
net.ipv6.conf.all.disable_ipv6 = 1  
net.ipv6.conf.default.disable_ipv6 = 1  
:wq  
sudo sysctl -p  
sudo systemctl restart network  

Filebeat prefers ipv6 so may cause issues  
sudo vi /etc/hosts  
dd the ::1 line to remove ipv6 line  

## Sudo notes
should do sudo -s as defense so that it logs when you root  
sudo su does not log  

## Look at repos & set to local repo
cd /etc/yum.repos.d/  
ls  
sudo rm -r CentOS-*  

sudo vi local.repo  
add the local-repo in insert mode  (under class-resources)
:wq  

Set to only local repo  
sudo yum makecache --disablerepo="*" --enablerepo="local*"  

Update repos  
sudo yum update  

List repos  
sudo yum list a*  

Reboot  
Just in case after all the repo updates  

SELinux  
cd /etc/selinux/  
vi/nano config  
*make sure SELINUX=enforcing  
getenforce (shows if on or not)  
/var/log/audit & /var/log/messages can be really useful for troubleshooting  

Optimize network interfaces:  
copy ifuplocal.sh to box  
sudo chmod a+x ifuplocal.sh  
./ifuplocal.sh  
