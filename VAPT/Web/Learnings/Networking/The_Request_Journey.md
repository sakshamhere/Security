


  Client Machine  -->     Home Router     --->  WAN (ISP)  ---> Web Server    
                      (Switch --> Router)

Things to cover - ARP to TCP, packets and many more
Network packet frame perspective
OSI Layers perspective

Some Facts

 - your home router is two devices: a switch and a router. 
 - Your LAN is essentially an Ethernet/Wifi network which works with MAC addresses.
 - The switch connects all the devices in your LAN together (including the router).
 - The router connects your switch(LAN) with the ISP(WAN) 
 - Any router delivers both DNS & DHCP services for the local network.
 - You're already running your own DHCP server in your router that gives out private IP addresses.
 - When your computer connects to the router, the router will tell the computer via DHCP which DNS server to use, and that will be the router’s internal DNS server.
 - Your router's DNS server typically forwards the dns queries "upstream" to ISP's DNS server and generally provide a few amount of nearby caching. But that still counts as a "DNS server". 
 - When a machine in you local netowork sends DNS query to your router, the router's inner DNS server first assessments if it can be responded from local cache, and if not, forwards it to your ISP's greater-succesful DNS servers.



First Client Machine needs to know the 

1. Once you enter the URL in browser, the browser needs to figure out which server to connect to and for that it performs `DNS Lookup`, it search the IP via DNS query in various caches
    - Browser Cache
    - OS Cache
    - Your Router's DNS server Cache
    - Your ISP's DNS Servers cache (This would be a corporate DNS server for a company's network)

If cannot find IP address at any of those cache's then  the DNS server on your corporate network or at your ISP does a `recursive DNS lookup.` A recursive DNS lookup asks multiple DNS servers around the Internet, which in turn ask more DNS servers for the DNS record until it is found.


2. Once the browser gets the DNS record with the IP address, it’s time for it to find the server on the Internet and establish a connection.


If the requested IP address is not local, then the client machine refers to its routing table to find out which gateway to send the packet to.

Hence in most circumstances the first packet sent out will be an ARP request to find the MAC address of the default gateway, if it's not already in the ARP cache.

Only then can it send the DNS query via the gateway. In this case the packet is sent with the DNS server's IP address in the IP destination field, but with the gateway's MAC address on the ethernet packet.