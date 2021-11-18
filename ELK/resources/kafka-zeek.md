# Zeek Kafka Script

Create the `kafka.zeek` script.

```vim
@load Apache/Kafka/logs-to-kafka
redef Kafka::topic_name = "zeek-raw";
redef Kafka::json_timestamps = JSON::TS_ISO8601;
redef Kafka::tag_json = F;
redef Kafka::send_all_active_logs = T;
redef Kafka::kafka_conf = table(
    ["metadata.broker.list"] = "<YOUR-SENSOR-IP>:9092");
```
