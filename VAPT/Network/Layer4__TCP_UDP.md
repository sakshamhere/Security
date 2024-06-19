

# TCP

21 - FTP
22 - SSH
23 - Telnet
25 - SMTP
80 - HTTP
443 - HTTPS
110 - POP3
139+445 - SMB
143 - IAMP


# UDP

53 - DNS
67, 68 - DHCP
69 - TFTP
161 - SNMP


Imagine a world without proper security measures at Layer 4
# Threats Without Layer 4 Security

- `TCP Handshake Hijack:` (Confidentiality)

TCP(Transport Control Protocol), being connection-oriented, relies on a three-way handshake to establish a secure connection. Without proper security measures, an attacker might intercept and manipulate this handshake, leading to unauthorized access or data manipulation.

- `Packet Injection Attacks:` (Integrity)

Without proper security measures at layer four an attacker could inject malicious packets into the data stream, exploiting the lack of data integrity checks.

- `UDP-Based Amplification Attacks` (Availablity)

UDP (User Datagram Protocol), being connectionless, is susceptible to abuse in the form of amplification attacks. Attackers can send small, forged requests to a vulnerable UDP service, causing it to respond with larger packets, and overwhelming the network.