# Address Resolution Protocol

ARP has one purpose: sending a frame to the broadcast address on the network segment/subnet and asking the computer with a specific IP address to respond by providing its `MAC (hardware) address`.

`For you to communicate with any device on your network, you must have the Ethernet MAC address for that device. If the device is not on your LAN, you go through your default gateway (your router). In this case, your router will be the destination MAC address that your PC will communicate with.`


The ARP protocol is designed to allow it to be used for any link-layer and network-layer protocols. OR . ARP is used to connect OSI Layer 3 (Network) to OSI Layer 2 (Data-Link).

However in practice it is only `used for local network(Ethernet/Samesubnet/LAN) and IPv4`. IPv6 uses NDP (neighbour discovery protocol) instead, which is a different protocol. 


ARP can only be used to identify devices in a subnet, even if there is any gateway attached to other subnet the request wont go outside current subnet.


If the system you are testing from has an address on the network you wish to scan, the simplest way to scan it is with a command similar to:

`arp-scan --interface=eth0 --localnet`


We can alo use Nmap

`nmap -PR -sn TARGETS`  (-PR indicates that you only want an ARP scan)

# ARP Request

This is nothing but broadcasting a packet over the network to validate whether we came across the destination MAC address or not. 

    The physical address of the sender.
    The IP address of the sender.
    The physical address of the receiver is FF:FF:FF:FF:FF: FF or 1’s.
    The IP address of the receiver.

# ARP Reply

It is the MAC address response that the source receives from the destination which aids in further communication of the data. 

`Note: An ARP request is broadcast, and an ARP Reply/response is a Unicast. `

# ARP Cache

After resolving the MAC address, the ARP sends it to the source where it is stored in a table for future reference. The subsequent communications can use the MAC address from the table.

You can manually populate the ARP cache using the arp command:

`arp -s <ipaddr> <macaddr>`

    E.g.: arp -s 192.168.1.1 192.168.1.1

You can see the contents of your ARP cache like this:

`arp an`

# ARP Cache Timeout

It indicates the time for which the MAC address in the ARP cache can reside.

***************************************************************************************************

# `ARP Spoofing` and `ARP Cache Poisoning`

ARP Spoofing is a type of falseness of a device in order to link the attacker’s MAC Address with the IP Address of the computer or server by broadcasting false ARP messages by the hacker. Upon successful establishment of the link, it is used for transferring data to the hacker’s computer. It is simply called Spoofing. ARP can cause a greater impact on enterprises. ARP Spoofing attacks can facilitate other attacks like:

    Man-in-the-Middle Attack
    Denial of Service Attack
    Session Hijacking