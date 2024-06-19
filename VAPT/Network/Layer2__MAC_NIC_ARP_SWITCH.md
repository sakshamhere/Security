https://www.tutorialspoint.com/network_security/network_security_data_link_layer.htm

In Layer 2 is the Data Link Layer, this basically includes protocols that manage movement of data arounf local network 

This includes protocl like MAC address, NIC

This inlcude devices like switch

# MAC Address / Physical Address

┌──(kali㉿kali)-[~]
└─$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.204.130  netmask 255.255.255.0  broadcast 192.168.204.255
        inet6 fe80::9d5c:a00d:b7e2:bfdf  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:0d:4f:91  txqueuelen 1000  (Ethernet)
        RX packets 369277  bytes 265894558 (253.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 329369  bytes 52347596 (49.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 396  bytes 36219 (35.3 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 396  bytes 36219 (35.3 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

*******************************************************************

`ether 00:0c:29:0d:4f:91`

MAC stands for `Media Access Control` , This is our physical address a

SWITCHES communicate on these phycial addresses, this is how they know what device is what.

Lets Say you built a laptop and installed a `NIC (Network Interface)` card, when you install it you are going to have a MAC address.

Anything that 's using a Network Interface will have a MAC address.

These MAC addresses are important because they utilise Layer 2 or switching and thats how we communicate via switches


MAC address - 00:0c:29:0d:4f:91

The first 3 pairs `00:0c:29` are identifiers , we can lookup for MAC just like DNS

https://aruljohn.com/mac/005056


MAC Addresses are related to Layer 2 which is related to Switching

# Security 

Many organizations incorporate security measures at higher OSI layers, from application layer all the way down to IP layer. However, one area generally left unattended is hardening of Data Link layer. This can open the network to a variety of attacks and compromises.

Data link Layer in Ethernet networks is highly prone to several attacks. The most common attacks are −

- ARP Spoofing
- MAC Flooding
- Port Stealing
- DHCP Attacks

# `ARP Spoofing`

`Address Resolution Protocol (ARP)` is a protocol used to map an IP address to a physical machine address recognizable in the local Ethernet. When a host machine needs to find a physical Media Access Control (MAC) address for an IP address, it broadcasts an ARP request. The other host that owns the IP address sends an ARP reply message with its physical address.

Each host machine on network maintains a table, called `‘ARP cache’`. The table holds the IP address and associated MAC addresses of other host on the network.

Since ARP is a stateless protocol, every time a host gets an ARP reply from another host, even though it has not sent an ARP request, it accepts that ARP entry and updates its ARP cache. `The process of modifying a target host’s ARP cache with a forged entry known as ARP poisoning or ARP spoofing.`

ARP spoofing may allow an attacker to masquerade as legitimate host and then intercept data frames on a network, modify or stop them. Often the attack is used to launch other attacks such as man-in-the-middle, session hijacking, or denial of service.


# `MAC Flooding`

Every switch in the Ethernet has a Content-Addressable Memory (CAM) table that stores the MAC addresses, switch port numbers, and other information. The table has a fixed size. In the MAC flooding attack, the attacker floods the switch with MAC addresses using forged ARP packets until the CAM table is full.

Once CAM is flooded, the switch goes into hub-like mode and starts broadcasting the traffic that do not have CAM entry. The attacker who is on the same network, now receives all the frames which were destined only for a specific host.


# `Port Stealing`

Ethernet switches have the ability to learn and bind MAC addresses to ports. When a switch receives traffic from a port with a MAC source address, it binds the port number and that MAC address.

The port stealing attack exploits this ability of the switches. The attacker floods the switch with forged ARP frames with the target host’s MAC address as the source address. Switch is fooled to believe that the target host is on port, on which actually an attacker is connected.

Now all data frames intended for the targeted host are sent to the attacker’s switch port and not to the target host. Thus, the attacker now receives all the frames which were actually destined only for the target host

# `DHCP Attacks`    

Dynamic Host Configuration Protocol (DHCP) is not a datalink protocol but solutions to DHCP attacks are also useful to thwart Layer 2 attacks.

DHCP is used to dynamically allocate IP addresses to computers for a specific time period. It is possible to attack DHCP servers by causing denial of service in the network or by impersonating the DHCP server. In a DHCP starvation attack, the attacker requests all of the available DHCP addresses. This results in a `denial of service` to the legitimate host on the network.

In `DHCP spoofing attack`, the attacker can deploy a rogue DHCP server to provide addresses to the clients. Here, the attacker can provide the host machines with a rouge default gateway with the DHCP responses. Data frames from the host are now guided to rouge gateway where the attacker can intercept all package and reply to actual gateway or drop them.