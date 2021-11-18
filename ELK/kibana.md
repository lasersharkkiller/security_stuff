## About
In our setup eth0/AF_PACKET > Ring Buffer > Zeek/Suricata > Zeek plugins/Eve.json-Filebeat > Kafka <> Logstash > Elasticsearch > Kibana  
Config: /etc/kibana/kibana.yml  
Config override files: /etc/sysconfig/service name  

## Config
```
sudo yum install elasticsearch kibana  
sudo -s
cd /etc/kibana
vi kibana.yml
server.host: "172.16.80.10"
elasticsearch.hosts: ["http://172.16.80.10:9200"]
:wq
```

```
firewall-cmd --add-port=5601/tcp --permanent
firewall-cmd --reload
```

```
sudo systemctl start kibana
sudo systemctl status kibana
sudo systemctl enable kibana
```

http://172.16.80.10:5601/  

Set up indeces:  
Left hamburger / Management / Stack Management  
Index patterns  / Create index pattern  
index pattern name: ecs-* :in our case we do both zeek & suricata in same index;  
Next / Time field: @timestamp  
Create Index Pattern  

Then we created separate indices for ecs-zeek-* and ecs-suricata-* supposedly for visualizations?  
If you do a curl 172.16.80.10:9200/_cat/indices we see the newly created system indices  

Left Hamburger / Management / Dev Tools  / Click to send request  
or GET /_cat/indices  
GET /_cat/health?v&pretty  
GET /_cat/shards?v&pretty  
*note this is the biggest consultant area - most people overshard, they don't set up lifecycle sharding (ILM) and so the shard get to like a TB and then the queries take forever  
