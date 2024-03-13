
` ARP `

We will leverage the protocols to discover the live hosts. Starting from bottom to top, we can use:

ARP from Link Layer
ICMP from Network Layer
TCP from Transport Layer
UDP from Transport Layer


        OSI 
        Application Layer           
        Presentation Layer          Application Layer           HTTP, HTTPS, FTP, SMTP, SSH, Telnet, RDP ...
        Session Layer
        Transport Layer             Transport Layer             TCP, UDP
        Network Layer               Network Layer               IPv4, IPv6, ICMP, IPsec
        Data Link Layer             Link Layer                  ARP, Ethernet, Wifi, Bluetooth
        Physical Layer


ARP, ICMP, TCP, and UDP can detect live hosts Any response from a host is an indication that it is online. Below is a quick summary of the command-line options for Nmap that we have covered.

Scan Type 	       Example Command

ARP Scan 	        sudo nmap -PR -sn MACHINE_IP/24
ICMP Echo Scan 	        sudo nmap -PE -sn MACHINE_IP/24
ICMP Timestamp Scan 	sudo nmap -PP -sn MACHINE_IP/24
ICMP Address Mask Scan 	sudo nmap -PM -sn MACHINE_IP/24
TCP SYN Ping Scan 	sudo nmap -PS22,80,443 -sn MACHINE_IP/30
TCP ACK Ping Scan 	sudo nmap -PA22,80,443 -sn MACHINE_IP/30
UDP Ping Scan 	        sudo nmap -PU53,161,162 -sn MACHINE_IP/30

Remember to add -sn if you are only interested in host discovery without port-scanning. Omitting -sn will let Nmap default to port-scanning the live hosts.


-n 	no DNS lookup
-R 	reverse-DNS lookup for all hosts
-sn 	host discovery only