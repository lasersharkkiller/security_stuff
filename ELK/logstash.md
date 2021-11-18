## About
*Note that the only licensing required at enterprise level is elasticsearch, the sales people might try to push ingest nodes but can be done with Logstash.
In our setup eth0/AF_PACKET > Ring Buffer > Zeek/Suricata > Zeek plugins/Eve.json-Filebeat > Kafka <> Logstash > Elasticsearch > Kibana  
Settings config: /etc/Logstash/conf.d  
Service config: /etc/Logstash/logstash.yml  
Config override files: /etc/sysconfig/service name  

## Config
sudo yum install logstash  
ls /etc/logstash/  
cat /etc/logstash/jvm.options :might want to give more RAM (Xms1g/Xmx1g)  

## Set up our normalization scripts
cd /etc/logstash/  
sudo curl -L -O http://192.168.2.20/share/logstash.tar.gz  
sudo tar xzvf logstash.tar.gz  
cd conf.d/  
ls :confirm new files  
rm logstash-100-input-kafka-fsf.conf :they got rid of fsf  
sudo vi logstash-100-input-kafka-zeek.conf :need to put our server ip in it  
sudo vi logstash-100-input-kafka-suricata.conf :need to put our server ip in it  
sudo vi logstash-9999-output-elasticsearch.conf :need to put our server ip in it 
 -in this case :%s/127.0.0.1/172.16.80.10/g :replaces all 127 addrs w/172..

```
sudo systemctl start logstash
sudo systemctl status logstash
sudo systemctl enable logstash
```

##### This is a manual example of post-parsing actions, we want to use the logstash.tar.gz files #####

Reference: https://www.elastic.co/guide/en/logstash/current/plugins-filters-mutate.html  
Reference: lesscolor /home/admin/conn.log :and other various logs show headers to compare against  

vi /etc/logstash/logstash.yml  
*In our case we don't have to make any of these changes but good to know:  
pipeline.batch.size:125 - if you monitor elastsearch apis and pull stats; if backpressure enabled elastic says i need you to stop or slow down (requested delay or back pressure or something along those lines); in that case reduce this number of pipeline.batch.size or put in a delay inside Logstash or beef up elasticsearch nodes. If no backpressure messages you can up this number to optimize.  
pipeline.id: main - enables to read the same data independently  
pipeline.workers: 2 - not the greatest, uncomment and adjust accordingly  
pipeline.unsafe_shudown: false - good in a dev environment; when you systemctl stop/restart doesn't wait for a minute to clear any back pressure, it just does it immediately  
X-Pack: can enable w/logstash so data sent is sent encrypted  


Next we create our input file for indexes, similar to Logstash topics. We don't do this here but you want to enable ILM (index lifecycle management) and when it hits 50Gb start a new one. Logstash topics are just a 7 day buffer, but indexes can be set to a file limit size.  
ls /etc/logstash/conf.d/ :nothing so far; we are about to create logstash pipeline config files that don't exist yet  
sudo vi /etc/logstash/conf.d/logstash-100-input-kafka-suricata.conf  
input {  
  kafka{  
    topics => ["suricata-raw"]  
    add_field => { "[@metadata][stage]" => "suricata_json" }  
    consumer_threads => 3  
    group_id => "suricata_logstash"  
    bootstrap_servers => "172.16.80.10:9092"  
    codec => json  
    auto_offset_reset => "earliest"  
    id => "input-kafka-suricata"  
  }  
}  

Next create our output file  
sudo vi /etc/logstash/conf.d/logstash-9999-output-elasticsearch.conf  
output {  
  file {  
    path => "/var/log/logstash/my-logs.txt"  
    codec => json  
  }  
}  

sudo systemctl start logstash  
sudo systemctl enable logstash  

Troubleshooting if something wrong w/your logstash  
cat/var/log/logstash/logstash-  
cat /var/log/logstash/logstash-plain.log  

View my-logs.txt file to ensure data incoming  
cat /var/log/logstash/my-logs.txt | jq ".stats.log"  

##Create a Zeek input/output file to separate from suricata
sudo vi /etc/logstash/conf.d/logstash-100-input-kafka-zeek.conf  
input {  
  kafka{  
    topics => ["zeek-raw"]  
    add_field => { "[@metadata][stage]" => "zeek_json" }  
    consumer_threads => 3  
    group_id => "zeek_logstash"  
    bootstrap_servers => "172.16.80.10:9092"  
    codec => json  
    auto_offset_reset => "earliest"  
    id => "input-kafka-zeek"  
  }  
}  
*you can find the topic names using /usr/share/kafka/bin/kafka-console-consumer.sh --bootstrap-server 172.16.80.10 --list

Next create our output file  
sudo vi /etc/logstash/conf.d/logstash-9999-output-elasticsearch.conf  
output {
  if [@metadata][stage] == "suricata_json" {
    file {
      path => "/var/log/logstash/my-logs.txt"
      codec => json
    }
  }
  else if [@metadata][stage] == "zeek_json" {
    file {
      path => "/var/log/logstash/zeek-logs.txt"
      codec => json
    }
  }
}

sudo systemctl restart logstash  

##Create our filters/mutations on suricata logs
filter{
    if [@metadata][stage] == "suricata_json" {
      mutate {
        convert => { "[flow_id]" => "string" }
        rename => {
          "proto" => "[network][transport]"
          "event_type" => "[event][dataset]"
          "flow_id" => "[event][id]"
          "community_id" => "[network][community_id]"
        }
        lowercase => [ "[network][transport]" ]
        add_field => {
          "[related][domain]" => []
          "[related][ip] => []
          "[event][created]" => "%{[@timestamp]}
        }
      }
    }
}

##### End of manual parsing #####
