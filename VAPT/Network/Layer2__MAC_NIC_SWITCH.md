
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