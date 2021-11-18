## About
http://rocknsm.io/  
In our setup Suricata writes an eve.json file. We have filebeat write to Kafka.  
Config: /etc/filebeat/filebeat.yml  
Config override files: /etc/sysconfig/service name  
Filebeat can only do one output, so we use the kafka_topic variable to output different topics under one output over to kafka but keep it under different topics  

## Config
```
sudo yum install filebeat  
cd /etc/filebeat  
```

```
sudo vi filebeat.yaml  
enabled: true  
Change /var/log/*.log to /data/suricata/eve.json:
  # Paths that should be crawled and fetched. Glob based paths.
  paths:
  - /data/suricata/eve.json
  json.keys_under_root: true

  fields:
    kafka_topic: suricata-raw
  fields_under_root: true


Shift+G to go to bottom to add  
##### Kafka outputs #####  
output.kafka:  
(2 spaces & ip is localhost)hosts: ["172.16.80.10:9092"]  
(2 spaces) topic: '%{[kafka_topic]}'  
(2 spaces) required_acks: 1  
(2 spaces) compression: gzip  
(2 spaces) max_message_bytes: 1000000  

comment out ElasticSearch Output section because like highlander there can be only one  

:wq 
```

Filebeat prefers ipv6 so may cause issues  
sudo vi /etc/hosts  
dd the ::1 line to remove ipv6 line 
:wq  
sudo systemctl restart network  
sudo systemctl restart zookeeper  
sudo systemctl restart kafka  

sudo systemctl start filebeat  
sudo systemctl status filebeat  
sudo systemctl start filebeat -l  
journalctl -xeu filebeat  

If still errors check the topics (for suricata-raw topic) 
sudo -s  
cd /usr/share/kafka/bin  
./kafka-topics.sh --bootstrap-server 172.16.80.10:9092 --list  
*Note we didn't see the topic  
./kafka-topics.sh --create --zookeeper 172.16.80.10:2181 --replication-factor 1 --partitions 8 --topic suricata-raw  
./kafka-topics.sh --bootstrap-server 172.16.80.10:9092 --list  (should now see suricata-raw)

Check to ensure firewall allow:  
firewall-cmd --list-ports  

Final check to make sure filebeat working as should (give it a little time to run); validating kafka shifted as expected  
sudo /usr/share/kafka/bin/kafka-console-consumer.sh --bootstrap-server 172.16.80.10:9092 --topic suricata-raw  

sudo systemctl start filebeat  
sudo systemctl status filebeat  
sudo systemctl enable filebeat  
