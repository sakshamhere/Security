# Active Recon

Moreover, we discuss using simple tools such as `ping,` `traceroute`, `telnet`, and `nc` to gather information about the network, system, and services.

Active reconnaissance requires you to make some kind of contact with your target, whether visiting their website or checking if their firewall has an SSH port open.

`ping,`

The primary purpose of ping is to check whether you can reach the remote system and that the remote system can reach you back. In other words, initially, this was used to check network connectivity; however, we are more interested in its different uses: checking whether the remote system is online.

`traceroute`
The purpose of a traceroute is to find the IP addresses of the routers or hops that a packet traverses as it goes from your system to a target host. This command also reveals the number of routers between the two systems. It is helpful as it indicates the number of hops (routers) between your system and the target host. However, note that the route taken by the packets might change as many routers use dynamic routing protocols that adapt to network changes.

`nc`