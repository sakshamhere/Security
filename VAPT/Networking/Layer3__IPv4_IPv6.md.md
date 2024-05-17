
Layer 3 is the Network Layer, this basically includes routing and devices like router

This includes Protocols like IPv4, IPv6, ICMP, IPSec


# IPv4 and IPv6

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

`inet 192.168.204.130`


128 64  32  16  4   2   1

1   1   1   1   1   1   1   = 255



128 64  32  16  4   2   1

0   0   0   0   1   1   1   = 7


So if we have an IP         7.7.7.7 
then it is bascially    000111.000111.000111.000111

So With IPv4 is 32 bit and we can have 2^32 = 4,294,967 possible IP addresses

But we are not just 4 billion people on earth , we are more and this adress space is exhausted


S0 we discovred IPv6 which 128 bit which is 2^128, this is a very large number and cant be exhausted 


BUT WAIT ! , we dont generally use IPV6 although it get assigned we still use IPv4 

HOW is that possible that we are using IPv4  but we are out address space?

Because We are using `NAT (Network Address Translation)`, so if we are using 20 devices in Home network those are not using IPs from that 4 billion but instead with NAT we have our private IP addresses assigned ex 192.168.204.130.

There are basically 3 class of private IP addresses

Class A - 10.0.0.0 - 10.255.255.255
Class B - 172.16.0.0 - 172.31.0.0
Class C - 192.168.0.0 - 192.168.255.255

So This is how we solve the IP address exhaution by using private IP address although we still can use IPV6 addresses

IPv4 and IPv6 are Layer 3 Protocols, Layer 3 is Netowrk Layer, which bacially provides network routing , includes devices like Router





