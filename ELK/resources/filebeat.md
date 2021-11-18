# Filebeat Configuration

Update/Configure your `filebeat.yml` configuration.

```vim
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /data/suricata/eve.json
  json.keys_under_root: true
  fields:
    kafka_topic: suricata-raw
  fields_under_root: true
- type: log
  enabled: true
  paths:
    - /data/fsf/logs/rockout.log
  json.keys_under_root: true
  fields:
    kafka_topic: fsf-raw
  fields_under_root: true
output.kafka:
  hosts: ["<YOUR-IP>:9092"]
  topic: '%{[kafka_topic]}'
  required_acks: 1
  compression: gzip
  max_message_bytes: 1000000
  ```
