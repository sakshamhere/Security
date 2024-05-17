
When port scanning with Nmap, there are three basic scan types. These are:

`ICMP ping sweep (-sn)`
`TCP Connect Scans (-sT)`
`SYN "Half-open" Scans (-sS)`
`UDP Scans (-sU)`


# Scan Types

# `ICMP ping sweep (-sn)`

This scan be used to scan the hosts alive on a network Nmap sends an ICMP packet to each possible IP address for the specified network. When it receives a response, it marks the IP address that responded as being alive.

# `TCP Connect Scans (-sT)`

This is by-default scan if we run without sudo which establish complete TCP three-way handshake connection ie `SYN ->, <- SYN-ACK, ACK ->`

# `SYN "Half-open" Scans (-sS)`

SYN scans are the default scans used by Nmap if run with sudo permissions. 

`"Half-open" scans, or "Stealth" scans.` In this unlike connect scan `SYN ->, <- SYN-ACK, RST -> ` , SYN scans sends back a RST TCP packet after receiving a SYN/ACK from the server (this prevents the server from repeatedly trying to make the request)

- It can be used to bypass older Intrusion Detection systems as they are looking out for a full three way handshake. This is often no longer the case with modern IDS solutions; it is for this reason that SYN scans are still frequently referred to as "stealth" scans. 

- SYN scans are often not logged by applications listening on open ports, as standard practice is to log a connection once it's been fully established.

- Without having to bother about completing (and disconnecting from) a three-way handshake for every port, SYN scans are significantly faster than a standard TCP Connect scan.

# `UDP Scans (-sU)`

Unlike TCP, UDP connections are stateless. This means that, rather than initiating a connection with a back-and-forth "handshake", UDP connections rely on sending packets to a target port and essentially hoping that they make it. 

When a packet is sent to an open UDP port, there should be no response. When this happens, Nmap refers to the port as being `open|filtered`. In other words, it suspects that the port is open, but it could be firewalled. If it gets a UDP response (which is very unusual), then the port is marked as `open`. More commonly there is no response, in which case the request is sent a second time as a double-check. If there is still no response then the port is marked open|filtered and Nmap moves on.

When a packet is sent to a `closed UDP port`, the target should respond with an ICMP (ping) packet containing a message that the port is unreachable. This clearly identifies closed ports, which Nmap marks as such and moves on.

# Scan States

`Open` - If Nmap sends SYN and recieves a SYN-ACK for it, in case of UDP when nmap gets a UDP response

`Closed` - if Nmap send SYN and recieves a reset flag ie RST fot it, in case of UDP target should respond with an ICMP (ping) packet containing a message that the port is unreachable

`Filtered` - if Nmap sends a TCP SYN request, and receives nothing or server send back RST TCP packet. `SYN ->, <- RST`. If the port is filtered by a firewall then the TCP SYN packet is either dropped, or spoofed with a TCP reset.

`open|filtered` - in case of UDP when nmap more commonly dosent recieve any response for request, its simply marks it as `open|filtered` and moves on.