## About
In our setup eth0/AF_PACKET > Ring Buffer > Zeek/Suricata > Zeek plugins/Eve.json-Filebeat > Kafka <> Logstash > Elasticsearch > Kibana  
Config: /etc/elasticsearch/elasticsearch.yml  
Config (other): /etc/elasticsearch/jvmoptions  
Config override files: /etc/sysconfig/service name    

## Config
```
sudo yum install elasticsearch kibana  
cd /data  
ls -la :see we need to make elasticsearch user the owner not root  
sudo chown -R elasticsearch: elasticsearch/  
cd /etc/elasticsearch 
``` 

```
cat /proc/meminfo | grep Mem :shows you how much RAM running  
sudo vi jvm.options   
In the JVM heap size -Xms4g/Xmx4g we want to set this to half our RAM up to 32Gb  
*Note on newer installs it says to set in jvm.options.d  
cp jvm.options jvm.options.d/  
sudo vi /etc/elasticsearch/jvm.options.d/jvm.options  
In the JVM heap size -Xms4g/Xmx4g we want to set this to half our RAM up to 32Gb:

##
-Xms16g
-Xmx16g
##
```

```
sudo vi /etc/elasticsearch/elasticsearch.yml  
cluster.name: name (like custard)  
node.name: name (like sensor1)  
path.data: /data/elasticsearch  
bootstrap.memory_lock: true :still need to ensure VMs don't have ballooning; same concept as SQL  
network.host: 172.16.80.10 :for clustering  
under Discovery tab, for single host instances, add discovery.type: single-node (otherwise set seed_hosts/zen nodes)  
```

```
Create our override file  
sudo mkdir -p /etc/systemd/system/elasticsearch.service.d  
cd /etc/systemd/system/elasticsearch.service.d  
sudo vi override.conf  
[Service]
LimitMEMLOCK=infinity
```

```
sudo firewall-cmd --add-port={9200,9300}/tcp --permanent
sudo firewall-cmd --reload
```

```
sudo systemctl start elasticsearch
sudo systemctl status elasticsearch
sudo systemctl enable elasticsearch
```

```
curl 172.16.80.10:9200
make sure name and cluster name to make sure config stuck
curl 172.16.80.10:9200/_cat
curl 172.16.80.10:9200/_cat/nodes?v :useful for troubleshooting nodes
curl 172.16.80.10:9200/_cat/health?v :useful for troubleshooting nodes
curl 172.16.80.10:9200/_cat/indices?v :useful for troubleshooting nodes
```

```
sudo systemctl start logstash
sudo systemctl status logstash
```

```
We want to put in our templates
rm -rf /data/elasticsearch/nodes/0/* :delete all data from our node, never do in prod
cd /home/admin
curl -L -O http://192.168.2.20/share/ecs-templates.tar.gz
tar -xzvf ecs-templates.tar.gz
cd ecs-configuration/elasticsearch/

sudo vi import-index-templates.sh
change ip

sudo systemctl start elasticsearch
./import-index-templates.sh :make sure none failed
if it fails, sudo systemctl restart elasticsearch and rerun script
curl 172.16.80.10:9200/_cat/indices?v :useful for troubleshooting nodes

sudo systemctl start logstash
sudo systemctl status logstash
```
