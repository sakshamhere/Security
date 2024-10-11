
The following are the five major DNS record types:

`A ` record
`AAAA`  record
`CNAME` record
`Nameserver (NS)` record
`Mail exchange (MX)` record

# A record

The "A" in A record stands for "address." An A record shows the IP address for a specific hostname or domain. The A record only supports IPV4 addresses. The main use of A record is for IP address lookup. Using an A record, a web browser is able to load a website using the domain name. As a result, we can access websites on the internet without knowing their IP addresses.

nslookup -type=A amazon.in

nslookup -type=A amazon.in 1.1.1.1 or nslookup -type=MX amazon.in 1.1.1.1  (if you want to use public DNS server and stay anonymous)

# AAAA record

AAAA record, just like A record, point to the IP address for a domain. However, this DNS record type is different in the sense that it points to IPV6 addresses.

nslookup -type=AAAA google.com

# CNAME record

CNAME—or, in full, "canonical name"—is a DNS record that points a domain name (an alias) to another domain. For example, the subdomain ng.example.com can point to example.com using CNAME. Here example.com points to the actual IP address using an A record. 

# NS record

A nameserver (NS) record specifies the authoritative DNS server for a domain. In other words, the NS record helps point to where internet applications like a web browser can find the IP address for a domain name. Usually, multiple nameservers are specified for a domain. For example, these could look like ns1.examplehostingprovider.com and ns2.examplehostingprovider.com.

# MX record

A mail exchange (MX) record, is a DNS record type that shows where emails for a domain should be routed to. In other words, an MX record makes it possible to direct emails to a mail server.

You can have multiple MX records for a single domain name. And what this means is that you can have backup email servers. 