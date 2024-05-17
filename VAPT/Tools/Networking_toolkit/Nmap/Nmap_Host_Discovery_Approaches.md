https://tryhackme.com/room/nmap01

# Different approaches used by Nmap to discover live hosts

- `ARP Scan`                (ARP from the Link layer (physical_data link layer))
- `ICMP Scan`               (ICMP from the Network layer)
- `TCP / UDP ping Scan`     (TCP/UDP from the Transport layer)


    Subnet 1
                                    Computer 1
            
            Computer 2               Switch                 Computer3


                                     Router

    Subnet 2 

            Computer 4               Switch                 Computer5

                                    Computer 6



- `ARP Scan`

ARP queires are basically used for address resolution ie to identify the MAC address of device, however this can be used to identify if host is online.

Nmap sends ARP requests to all the target computers, and those online should send an ARP reply back.

        ARP Request -->
        <-- ARP Reply

ARP can only be used to identify devices in a subnet, even if there is any gateway attached to other subnet the request wont go outside current subnet.

ARP has one purpose: sending a frame to the broadcast address on the network segment/subnet and asking the computer with a specific IP address to respond by providing its MAC (hardware) address.

For Example - you send a ARP Broadcast request, which will be from computer 1 to computer1 itself , and data you send computer 6 (because we are asking for computer6 MAC address using ARP Request), Now in this case the request will go to all computer in subnet 1 however it wont go out of it


- `ICMP Scan` / `ICMP echo`

If you do a ICMP ping to any computer then the ping reqiest precedes or goes after the ARP request to that computer

For Example  - you send Ping request from computer1 to computer3 which is in same subnet

    ARP REQUEST: Who has computer3 tell computer1
    ARP RESPONSE: Hey computer1, I am computer3
    PING: Sending Ping Request packet from computer1 to computer3
    PING: computer3 received ping request from computer1, sending ping response to computer1
    PING: Sending Ping Response packet from computer3 to computer1

For Example - you send Ping request from computer 2 to computer 5 which is in another subnet

    ROUTING: computer2 says computer5 is not on my local network sending to gateway: router
    ARP REQUEST: Who has router tell computer2
    ARP RESPONSE: Hey computer2, I am router
    PING: Sending Ping Request packet from computer2 to computer5
    ARP REQUEST: Who has computer5 tell router
    ARP RESPONSE: Hey router, I am computer5
    PING: computer5 received ping request from computer2, sending ping response to computer2
    PING: Sending Ping Response packet from computer5 to computer2
    PING: computer2 received ping response from computer5


We can ping every IP address on a target network and see who would respond to our ping (ICMP Type 8/Echo) requests with a ping reply (ICMP Type 0). Simple, isn’t it? Although this would be the most straightforward approach, it is not always reliable. Many firewalls block ICMP echo; new versions of MS Windows are configured with a host firewall that blocks ICMP echo requests by default. Remember that an ARP query will precede the ICMP request.

`Remember that an ARP query will precede the ICMP request`

You'll note that the ARP request only happens the first time you run ping. If you run it a second time (shortly after the first run), you'll see that the ping start immediately with an ICMP request. This is because when a system discovers the IP address/MAC address association via ARP, it stores the result in a local `arp cache`.


An ICMP echo scan works by sending an ICMP echo request and expects the target to reply with an ICMP echo reply if it is online.

        ICMP Echo Request ---->
        <-----  ICMP Echo Reply

Nmap follows the following approaches to discover live hosts:

1. For Privileged User

When a privileged user (sudoers) tries to scan targets on local network(Ethernet/Samesubnet/LAN), nmap uses 
    - ARP requests.

When a privileged user (sudoers) tries to scan targets outside the local network, nmap uses
    - ICMP echo requests
    - TCP ACK (Acknowledge) to port 80
    - TCP SYN (Synchronize) to port 443
    - ICMP timestamp requests

2. For Unprivileged User

When an unprivileged user tries to scan outside local network, nmap resorts to a TCP 3-way  handshake by sending SYN packets to ports 80 and 443


- `ICMP Timestamp requests`

Because ICMP echo requests tend to be blocked, you might also consider ICMP Timestamp or ICMP Address Mask requests to tell if a system is online. Nmap uses timestamp request (ICMP Type 13) and checks whether it will get a Timestamp reply (ICMP Type 14). Adding the -PP option tells Nmap to use ICMP timestamp requests. As shown in the figure below, you expect live hosts to reply.

- `ICMP Address mask queries`

Similarly, Nmap uses address mask queries (ICMP Type 17) and checks whether it gets an address mask reply (ICMP Type 18). This scan can be enabled with the option -PM. As shown in the figure below, live hosts are expected to reply to ICMP address mask requests.

- `TCP SYN Ping`

We can send a packet with the SYN (Synchronize) flag set to a TCP port, 80 by default, and wait for a response. An open port should reply with a SYN/ACK (Acknowledge); a closed port would result in an RST (Reset). 

For Privileged User,

    Privileged users (root and sudoers) can send TCP SYN packets and don’t need to complete the TCP 3-way handshake even if the port is open

        SYN ->
        <- SYN/ACK
        RST ->

For Non-privileged users

    Unprivileged users have no choice but to complete the 3-way handshake if the port is open.
        SYN ->
        <- SYN/ACK
        ACK ->

- `TCP ACK Ping`

As you have guessed, this sends a packet with an ACK flag set. You must be running Nmap as a privileged user to be able to accomplish this. If you try it as an unprivileged user, Nmap will attempt a 3-way handshake.

    ACK ->
    <- RST


- `UDP Ping`

 Contrary to TCP SYN ping, sending a UDP packet to an open port is not expected to lead to any reply. However, if we send a UDP packet to a closed UDP port, we expect to get an ICMP port unreachable packet; this indicates that the target system is up and available.

 For online host

    UDP Packet ->

 For offline host

    UDP Packet ->
    <- ICMP type3, code3   ( ICMP port unreachable packet;)


