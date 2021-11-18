## Troubleshooting:
Verify there is actually a problem first  
Check network cable  
check interface (ip a|grep state OR tcpdump interface)  
systemctl status service  
systemctl status zeek suricata stenographer zookeeper kafka filebeat kibana logstash elasticsearch | grep -A2 -B2 Active  
firewall-cmd --list-ports (1234, 2181, 5601, 9092, 9200, 9300, 9600)  
systemctl restart service  
Journalctl - look for AccessDenied; ll the path  
permission denied, access not found, port already bound  
Logstash broker may not be available - (kafka is broker check that)  
Check service configuration files  
Elasticsearch stores its license inside itself  
Suricata logs not showing up in Kibana index - check Logstash json_keys_under_root
