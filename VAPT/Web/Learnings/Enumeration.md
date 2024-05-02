

The whole enumeration process is divided into three different levels:

# 1. Infrastructure-based enumeration 	

# 2. Host-based enumeration 	

# 3. OS-based enumeration


These layers are designed as follows:

# 1. Internet Presence

Identification of internet presence and externally accessible infrastructure.

Domains, Subdomains, vHosts, ASN, Netblocks, IP Addresses, Cloud Instances, Security Measures etc

# 2. Gateway 	

Identify the possible security measures to protect the company's external and internal infrastructure. 	

Firewalls, DMZ, IPS/IDS, EDR, Proxies, NAC, Network Segmentation, VPN, Cloudflare etc

# 3. Accessible Services 	

Identify accessible interfaces and services that are hosted externally or internally. 	

Service Type, Functionality, Configuration, Port, Version, Interface

# 4. Processes 	

Identify the internal processes, sources, and destinations associated with the services. 	

PID, Processed Data, Tasks, Source, Destination

# 5. Privileges 	

Identification of the internal permissions and privileges to the accessible services. 	

Groups, Users, Permissions, Restrictions, Environment

# 6. OS Setup 	

Identification of the internal components and systems setup. 	

OS Type, Patch Level, Network config, OS Environment, Configuration files, sensitive private files


******************************************************************

# OSINT

# 1. Domain Information

- Company Website

Get basic understanding of the company and its services,


- # `Online Presence`

- SSL Certificate

The first point of presence on the Internet may be the SSL certificate from the company's main website that we can examine. Often, such a certificate includes more than just a subdomain, and this means that the certificate is used for several domains, and these are most likely still active.

* This also helps us to find subdomains.

- https://crt.sh

This source is for "Certificate Transparency" logs.

This is intended to enable the detection of false or maliciously issued certificates for a domain.

Certificate Transparency - The security of HTTPS depends on the trust that certificates are only given out by the certificate authority that was requested by the owner of some website or IT infrastructure. Certificate Transparency has the potential to expose certificates that were given out without them being requested by the genuine owner.

SSL certificate providers like "Let's Encrypt" share this info with the web interface like "crt.sh", which stores the new entries in the database to be accessed later.

for example - https://crt.sh/?q=amazon.in

We can also get Json output - https://crt.sh/?q=amazon.in&output=json

* This also helps us to find many subdomains. If needed, we can also have them filtered by the unique subdomains.


# 3. ` Company Hosted Servers`

Next, we can identify the hosts directly accessible from the Internet and not hosted by third-party providers. This is because we are not allowed to test the hosts without the permission of third-party providers.

consider inlanefreight.com in this example


Doshi@htb[/htb] `for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done`

blog.inlanefreight.com 10.129.24.93
inlanefreight.com 10.129.27.33
matomo.inlanefreight.com 10.129.127.22
www.inlanefreight.com 10.129.127.33
s3-website-us-west-2.amazonaws.com 10.129.95.250


Once we see which hosts can be investigated further, we can generate a list of IP addresses with a minor adjustment to the cut command and run them through `Shodan.`

# `Shodan serach on IPs`

Shodan can be used to find devices and systems permanently connected to the Internet like Internet of Things (IoT). 

It searches the Internet for open TCP/IP ports and filters the systems according to specific terms and criteria. For example, open HTTP or HTTPS ports and other server ports for FTP, SSH, SNMP, Telnet, RTSP, or SIP are searched. 

As a result, we can find devices and systems, such as surveillance cameras, servers, smart home systems, industrial controllers, traffic lights and traffic controllers, and various network components.

# `DNS Records`

We got 
- `A` Record which we already know apart from that 
- `NS` Record which are nameservers used to resolve FQDN to IP address
- `MX` Records which are mail servers
- `TXT` Records which gives more info

for example - `dig @8.8.8.8 any booking.com`


# 2. Cloud Resources

Even though cloud providers secure their infrastructure centrally, this does not mean that companies are free from vulnerabilities.

This often starts with the `S3 buckets` (AWS), `blobs (Azure)`, `cloud storage (GCP)`, which can be accessed without authentication if configured incorrectly.