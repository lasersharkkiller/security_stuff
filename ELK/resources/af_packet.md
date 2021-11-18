# Zeek Script for AF_Packet

Create the `af_packet.zeek` script and use the following code:

```vim
redef AF_Packet::fanout_id = strcmp(getenv("fanout_id"),"") == 0 ? 0 : to_count(getenv("fanout_id"));
```
