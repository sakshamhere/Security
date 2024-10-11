# Link-Local Multicast Name Resolution 

`LLMNR` is a protocol that allows both IPv4 and IPv6 hosts to `perform name resolution for hosts on the `same local network` without requiring a DNS server` or DNS configuration.

When a host’s DNS query fails (i.e., the DNS server doesn’t know the name), the host broadcasts an LLMNR request on the local network to see if any other host can answer.

LLMNR was previously known as `NetBIOS`, `NBT-NS` is a component of NetBIOS over TCP/IP (NBT) and is responsible for name registration and resolution.  

Like LLMNR, NBT-NS is a fallback protocol when DNS resolution fails. It allows local name resolution within a LAN.


# Security risk

It is vulnerable to MITM attack - LLMNR Poisioining

LLMNR has no authentication mechanism.  Anyone on network can respond to an LLMNR request, which opens the door to potential attacks. When a computer tries to resolve a domain name and fails via the standard methods (like DNS), it sends an LLMNR query across the local network.  An attacker can listen for these queries and respond to them, leading to potential unauthorized access.

Attacker runs `Responder` on network and when a LLMNR event occurs in the network and is maliciously responded to, the attacker will obtain sensitive information, including:

- The IP address of the victim 

- The domain and username of the victim 
    
- The victim’s password hash

Further he can crack this hash and gain password


# Mitigation -> Main Defense – Disable LLMNR and NBT-NS

To disable LLMNR, select “Turn OFF Multicast Name Resolution” under Computer Configuration > Administrative Templates > Network > DNS Client in the Group Policy Editor.