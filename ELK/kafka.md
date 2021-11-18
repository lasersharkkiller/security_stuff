## About
Note that Kafka is important even if it seems like overhead. Some try to access Zeek's logs from Filebeat; do not do because this causes mass latency - you can only read OR write. Zeek is always writing and so FileBeat will keep waiting and waiting.  

Config: /etc/kafka/serviceproperties.conf  
Config override files: /etc/sysconfig/service name  

Why Kafka vs RabbitMQ or Celery or whatever? Lots of message queues have optimitized the producer <> Queue. The problem comes in between the Queue <> Consumer, where Kafka optimizes. Kafka puts responsibility on consumer which pointer in system they are currently at - i.e. logstash's job to remember which pointer at. So consumer asks for pointer 3, and puts responsibility on consumer to confirm they got it. It eliminates alot of network traffic and makes efficient.  
  
Kafka has a frontend called ZooKeeper. Kafka keeps cluster shards which replicates data for redundancy. Say you have K1-K4 in your cluster. You can set up a backup Kafka manager (like K3). Once network reestablishes the manager goes to the majority of instances, but if you have 2/2 split it requires manual intervention. Better to have an odd # of kafka instances.  

Kafka partition shards need to match the number of disks or it will cause performance issues. Note you can never decrease the number of partition shards.

Replica #s max can only be Partition shards -1. If you have 3 disks you can only have 2 replicas. Replicas cannot exist on the same node.  

## Zookeeper Setup
sudo yum install zookeeper kafka  
sudo vi /etc/zookeeper/zoo.cfg : no changes in our case for standalone; if cluster add servers  
sudo systemctl start zookeeper  
sudo systemctl enable zookeeper  
sudo systemctl status zookeeper  
sudo systemctl enable zookeeper  

## Kafka Setup
sudo vi /etc/kafka/server.properties  
uncomment listeners=PLAINTEXT://172.16.80.10:9092  
advertised.listeners=PLAINTEXT://172.16.80.10:9092  
log.dirs=/data/kafka  
num.partitions=3 :number of partitions needs to be greater than the number that read from it  (defines max throughput, no performance hit for having a ton)  
log.retention.bytes=90000000000 :when a message is read deleted but kafka doesnt  

Set permissions  
sudo chown -R kafka: /data/kafka/  
sudo firewall-cmd --add-port=2181/tcp --permanent  
sudo firewall-cmd --add-port=9092/tcp --permanent  
sudo firewall-cmd --reload  
systemctl start kafka  
sudo systemctl status kafka  
sudo systemctl enable kafka  

Test: 
cd /usr/share/kafka/bin
./kafka-topics.sh --bootstrap-server 172.16.80.10:9092 --list :right now probably dont have topics until zeek  
./kafka-topics.sh --bootstrap-server 172.16.80.10:9092 --topic zeek-raw --describe :right now probably dont have topics until zeek  


sudo vi /usr/share/zeek/site/scripts/kafka.zeek  
# Zeek Kafka Script
```vim
@load Apache/Kafka/logs-to-kafka
redef Kafka::topic_name = "zeek-raw";
redef Kafka::json_timestamps = JSON::TS_ISO8601;
redef Kafka::tag_json = F;
redef Kafka::send_all_active_logs = T;
redef Kafka::kafka_conf = table(
    ["metadata.broker.list"] = "172.16.80.10:9092");
```

sudo vi /usr/share/zeek/site/local.zeek  
Shift+G; add @load ./scripts/kafka.zeek  
sudo systemctl restart zeek  
sudo systemctl status zeek  
sudo /usr/share/kafka/bin/kafka-topics.sh --bootstrap-server 172.16.80.10:9092 --list :should now see a zeek-raw  
sudo /usr/share/kafka/bin/kafka-topics.sh --bootstrap-server 172.16.80.10:9092 --topic zeek-raw --describe  
sudo /usr/share/kafka/bin/kafka-console-consumer.sh --bootstrap-server 172.16.80.10:9092 --topic zeek-raw  
To test, ssh in a separate terminal, curl www.google.com  
