## Hardware / Software flow
Supposedly on eth0 capture use AF_Packet & best chip to use supposedly is Intel X-710 ($2k/card - 10Gbps no problem)  
Eth0 / AF_packet > Ring Buffer > Stenographer, Zeek, Suricata  
## About
In our setup eth0/AF_PACKET > Ring Buffer > Zeek/Suricata > Zeek plugins/Eve.json-Filebeat > Kafka <> Logstash > Elasticsearch > Kibana

Note that separate disk clusters should be set up for OS / various tools like stenographer, Zeek, Suricata. Disks can either read or write.

## Alternatives
PFRing - but PFRing costs money, plus there are two versions. AF_PACKET is better performance than PFRing free (PF0) according to instructor tests (4% packet loss w/PFRing and negligible w/AF_PACKET)  
N2TOP is another alternative.
