## About
Zeek is NSM portion formerly known as Bro  
Zeek > Zeek logs/plugins > Kafka (Logs write to disk, plugins send directly to Kafka so read/write isn't issue)  

Config: /etc/zeek (RockNSM)  
Scripts: /usr/share/zeek  
Config override files: /etc/sysconfig/service name  
  
Note that Kafka is important even if it seems like overhead. Some try to access Zeek's logs from Filebeat; do not do because this causes mass latency - you can only read OR write. Zeek is always writing and so FileBeat will keep waiting and waiting.  
  
Kafka has a frontend called ZooKeeper. Kafka keeps cluster shards which replicates data for redundancy. Say you have K1-K4 in your cluster. You can set up a backup Kafka manager (like K3). Once network reestablishes the manager goes to the majority of instances, but if you have 2/2 split it requires manual intervention. Better to have an odd # of kafka instances.  

Kafka partition shards need to match the number of disks or it will cause performance issues. 

# Install Zeek

yum install zeek via RPM  
`yum install zeek zeek-plugin-af_packet zeek-plugin-kafka`

### Configure Zeek
```
sudo vi /etc/zeek/networks.cfg (location /etc/zeek/ from RockNSM install, may vary)  
You can set subnet tags here  
zeek-config --config_dir :tells you where your config file is  
zeek-config --script_dir :tells you where your script config file is  
```

```
sudo vi /etc/zeek/zeekctl.cfg  
SitePolicyScripts = local.zeek :most common across community, anything you want to enable/disable  
LogDir = /data/zeek :we created a separate partition to help with iops  
lb_custom.InterfacePrefix=af_packet:: -have to type out ourselves; this will append af_packet to the front of our packets across multiple interfaces  
```

```
sudo vi /etc/zeek/node.cfg :if you have multiple zeek sensors, only build out node config on manager zeek; will log in as zeek user - must set up passwordless login on each zeek sensor. For every ~20Gib of traffic throughput you need a manager. Per core you can get ~100M(bit not byte) of traffic processed with most scripts and stuff; Corelight says 250Mb per core but not as much turned on  
:set nu   :sets numbering in vi
in our case we commented out 8-11, the part about being standalone, and uncommented everything below (minus the two lines of comments immediately below) 
in command mode cntrl+V arrow down, to delete all comments  
we don't need a worker2 in our case but we are going to set up threading  
under [manager] we add the line:  
pin_cpus=1 :this specifies the specific core 1, not that it is 1 core. Do NOT use zero that is OS  
Under [worker-1]
change interface= (in our case enp5s0)  
lb_method=custom  
lb_procs=2  
pin_cpus=2,3 :give the worker cores 2+3  
env_vars=fanout_id=77 :anything over 10 should be good  
```
```vim
sudo mkdir /usr/share/zeek/site/scripts :set up custom location so if you upgrade zeek it doesn't get blown away. In this script we change the fanout_id variable to two different ring buffers  
sudo vi /usr/share/zeek/site/scripts/af_packet.zeek  

redef AF_Packet::fanout_id = strcmp(getenv("fanout_id"),"") == 0 ? 0 : to_count(getenv("fanout_id"));
```

Script to modify how records recorded in Zeek: (or use extension script in class resources)  
sudo vi /usr/share/zeek/site/scripts/extension.zeek  
```vim
`type Extension: record {
    stream: string &log;
    system: string &log;
    proc: string &log;
};
function add_log_extension(path: string): Extension {
    return Extension($stream = path,
      $system = "sensor1",
      $proc = peer_description);
}
redef Log::default_ext_func = add_log_extension;
redef Log::default_ext_prefix = "@";
redef Log::default_scope_sep = "_";
```

Next we update our local.zeek to add scripts; if zeek updates, need to update this  
sudo vi /usr/share/zeek/site/local.zeek  
*there are alot of cool things you can turn on
Shift+G to drop to bottom, i to insert. 
Add:  
`@load ./scripts/af_packet.zeek  
@load ./scripts/extension.zeek`

Zeek by default runs as root, we want to run as user.  
ll -a /etc/zeek :shows owned by root  
sudo chown -R zeek: /etc/zeek  
sudo chown -R zeek: /data/zeek  
sudo chown -R zeek: /usr/share/zeek  
sudo chown zeek: /usr/bin/zeek  
sudo chown zeek: /usr/bin/capstats  
sudo setcap cap_net_raw,cap_net_admin=eip  /usr/bin/zeek :since downgrading to usr giving permission to binary  
sudo setcap cap_net_raw,cap_net_admin=eip  /usr/bin/capstats :since downgrading to usr giving permission to binary  
sudo getcap /usr/bin/zeek  

systemctl cat zeek.service :the rpm (RockNSM) we install drops down privs but not always the case  
sudo systemctl start zeek  
sudo systemctl enable zeek

Validate Zeek is capturing traffic:  
curl www.google.com  
cd /data/zeek/current  
tail conn.log :best way to check traffic passing is check conn.log  
