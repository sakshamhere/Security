
When you Ping a target or send Ping request a target you first need to know the MAC address of that target, so thats why when you send Ping request first ARP request is send and them after getting ARP reply Ping request is send.

You'll note that the ARP request only happens the first time you run ping. If you run it a second time (shortly after the first run), you'll see that the ping start immediately with an ICMP request. This is because when a system discovers the IP address/MAC address association via ARP, it stores the result in a local `arp cache.` Entries in the cache do expire after some amount of time.

