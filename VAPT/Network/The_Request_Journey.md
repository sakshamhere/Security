https://medium.com/@hnasr/the-networking-behind-clicking-a-link-b2ce36b7cf14


  Client Machine  -->     Home Router     --->  WAN (ISP)  ---> Web Server    
                      (Switch --> Router)

Things to cover - ARP to TCP, packets and many more
Network packet frame perspective
OSI Layers perspective

Some Facts

 - your home router is two devices: a switch and a router. 
 - Your LAN is essentially an Ethernet/Wifi network which works with MAC addresses.
 - The switch connects all the devices in your LAN together (including the router).
 - The router connects your switch(LAN) with the ISP(WAN) 
 - Any router delivers both DNS & DHCP services for the local network.
 - You're already running your own DHCP server in your router that gives out private IP addresses.
 - When your computer connects to the router, the router will tell the computer via DHCP which DNS server to use, and that will be the router’s internal DNS server.
 - Your router's DNS server typically forwards the dns queries "upstream" to ISP's DNS server and generally provide a few amount of nearby caching. But that still counts as a "DNS server". 
 - When a machine in you local netowork sends DNS query to your router, the router's inner DNS server first assessments if it can be responded from local cache, and if not, forwards it to your ISP's greater-succesful DNS servers.

# Findings IP - DNS Lookup, DNS Resolution

1. Once you enter the URL in browser, the browser needs to figure out which server to connect to and for that it will perform `DNS Lookup`.

  - it search the IP via DNS query in various caches
      - Browser Cache
      - OS Cache
  
  - If the requested IP address is not local, then the client machine refers to its routing table to find out which gateway to send the packet to.

  - In most circumstances the first packet sent out will be an `ARP request` to find the MAC address of the default gateway, if it's not already in the ARP cache.

  - Then it sends the DNS query via the gateway. In this case the packet is sent with the DNS server's IP address in the IP destination field, but with the gateway's MAC address on the ethernet packet. DNS lookup will be performed in below caches.
    - Your Router's DNS server Cache
    - Your ISP's DNS Servers cache (This would be a corporate DNS server for a company's network)

2. If DNS record is not found in any of the cache, then the request goes `DNS recursor`/`DNS Resolver`, this could be Google 8.8.8.8 or Cloudflare’s 1.1.1.1 and in case of corporate it might be their own DNS Server. `DNS recursor` does `recursive DNS lookup.` until DNS record is found.

  - The recursor asks the `ROOT DNS servers` for a `.com` top level domain server `(TLD) server`. The `root servers` act as the DNS backbone of the internet; their job is to redirect you to the correct `Top Level Domain Server`.

  - The recursor then send a query to a TLD server asking for the `authorative`/ `name server` where xyz.com is hosted, 

  - TLD server returns one of the DNS authoritative name server like  for example GoDaddy.

  - Finally the recursor sends the DNS query  to Godaddy server to get the IP address for xyz.com

  - So Recusrsor now does a new DNS query to resolve `zen-mccarthy-34c0bb.netlify.app` and the process is repeated until an IP address is discovered.

  - Recursor then discovers that xyz.com is a `CNAME (Canonical Name)` that points to `zen-mccarthy-34c0bb.netlify.app`.

# TCP Connection Establishment - TCP 3 way handshake

3. Now that we know IP address, TCP connection will be established, Establishing TCP connection requires 4 tuples, source IP, source port, destination IP and destination Port. The client needs all four before it can connect.

  - The client knows the destination IP thanks to DNS, the destination port is 443 since the link explicitly says https://. The source port can be any available port between 0–2¹⁶ and the source IP is your machine.

  - While the source IP might normally start as the machine private IP address, it changes to the gateway’s public IP address before it leaves private network, a process called `NAT or Network address translation`. The source port also changes and an entry is added to the NAT table to remember what the change was made so the gateway knows how to forward the packets back to the original machine

4. With theese 4 tuples, the client sends a SYN TCP segment carried in an IP packet, the server gets the SYN and replies back with SYN/ACK changing the destination IP to the client’s IP ( which is the gateway more likely) and finally the client finishes the handshake with the ACK. We now have a connection

Client ------------SYN ------->  (35.247.66.204)
       <---------SYN/ACK------
       ------------ACK-------->

# TLS handshake - Encrypting TCP Connection

5. Any data sent on the TCP connection at its current state is plain text and can be observed by anyone intercepting traffic. That is why the communication is encrypted using TLS to ensure security. A TLS handshakes occur after a TCP connection has been opened via a TCP handshake.

  - In a nutshell, TLS handshake process — entails exchanging messages between the server and the client. They define the settings of the encrypted communication, including enabled cipher suites, protocol version, renegotiation security, and others.

  - First Client approaches server on port 443 with a `ClientHello1` message, This message contains A 32-byte random number known as `Client Random`, Maximum TLS version supported by the client and List of Ciphers that client supports

  - Server then decides what TLS version, Ciphers are availible and the resplies with `ServerHello` with Selected TLS version and Cipher, A newly generated random number `Server Random`, Server's own SSL Certificate with a public key and a digital Signature.

  - Client then Verifies Certificate, client generates a Pre-master key encrypt it using CA public key and send it to server.

  - Server decrypts message sent by client using CA private key and it also gets Pre-master key

  - So now both Client and Server has pre-master key, Client Randome, and Server Random.

  - So using all these 3 things they both generate a Master key. using this master key symmetric keys will be derived which will be used to have encrypted connection from both sides.


6. The client sets many `TLS extensions` as part of its `client hello` message, there are two interesting out of them. The first is `ALPN` which stands for `application layer protocol negotiation` and the second is `SNI` which stands for `Server name indication`. 

  - `ALPN `is a TLS extension that indicates the application protocols the client supports. The client can propose both `HTTP/1.1 and HTTP/2 (h1 and h2 for short)` as part its ALPN and the highest protocol supported by both client and server is usually selected.

  - `SNI` extension indicates to the server what domain the client is interested in. This is because one IP address can host thousands of websites, and indicating the domain helps the server know exactly what website the client is interested in, so the server knows what certificate to return.


# HTTP Request - HTTP/1.1 or HTTP/2 stream and headers

7. Now that we have encrypted TCP connection, client needs an HTTP stream to send the request on. suppose The application layer protocol of choice is HTTP/2. The client sets the HTTP headers and sends the request.