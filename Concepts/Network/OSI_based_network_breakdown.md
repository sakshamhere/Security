

# Application Layer / Layer 7
`Description ` -
`Protocols` - HTTP, FTP, SMB/CIFS, TFTP, SMTP
`Devices` - 
`Security Considerations` - HTTPS
`Common Threats` -

# Presentation Layer
`Description ` -
`Protocols` -
`Devices` - 
`Security Considerations` - 
`Common Threats` - Cracking encryption, Injection attacks,File inclusion, Cross-site scripting (XSS), Cross-site request forgery (CSRF)

# Session Layer
`Description ` -
`Protocols` -
`Devices` - 
`Security Considerations` - 
`Common Threats` - Session hijacking, Access control bypass, MITM attacks


# Trasnport Layer /Layer 4
`Description ` -
    - Reliable transport: Layer 4 protocols, such as TCP (Transmission Control Protocol), provide reliable transport by establishing a connection between devices, ensuring that data is delivered in the correct order, and retransmitting lost or corrupted packets
    - Efficiency: The transport layer is responsible for segmenting data into smaller units, known as segments, to optimize the use of network resources and improve efficiency. It also ensures that data is transmitted at a rate that the receiver can handle, by using flow control mechanisms such as sliding window protocols.

`Protocols` 
    - TCP, UDP
`Devices` - 
`Security Considerations` - SSL/TLS, SSH, Firewall
`Common Threats` - TCP/UDP port scanning, DNS poisoning, Lateral Movement

# Network / Layer 3
`Description ` - 
    - Its Basic work is to encapsulate data recieved from trasnport layer into packets and transfer them to to DLL.
    - It decides the route through which this packet transfer should be done
`Protocols` - IPV4, IPV6, ICMP, IPSec
`Devices` - Router
`Security Considerations` - IPSec (providing VPN)
`Common Threats` - ICMP Redirect, UDP Floods, SYN Floods

# Data Link / Layer 2
`Description ` - 
    - DLL recieves data packets from network layer, devides packets into frames and send those frames bit-by-bit to underlying physical layer.
    - It encapsulates MAC address in header of each frame.
`Protocols` - MAC, NIC, ARP
    - Anything which has Network Interface will have Media Control Access/Physical Address
    - Address Resolution protocol is used to map the MAC with IP address
`Devices` - Switch  
    - Switches communicate using MAC address
`Security Considerations` -  
`Common Threats` - ARP Spoofing, MAC Flooding, Port Stealing   

# Physical
`Description `- Transmits raw bits (0/1) over physical medium
`Devices` - LAN cable
`Security Considerations` - 
`Common Threats` - Tampering with physical connections


