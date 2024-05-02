# Passive Recon

- `whois`
- `nslookup`
- `dig`
> `DNSdumpster`


1. Find DNS server and Get various information about the domain name using `Whois` .

The `WHOIS` server replies with various information related to the domain requested. Of particular interest, we can learn:

    Registrar: Via which registrar was the domain name registered?
    Contact info of registrant: Name, organization, address, phone, among other things. (unless made hidden via a privacy service)
    Creation, update, and expiration dates: When was the domain name first registered? When was it last updated? And when does it need to be renewed?
    Name Server: Which server to ask to resolve the domain name?

2. Find IP address of domain name using `nslookup`

Syntex - 
nslookup DOMAIN_NAME - Find the IP address of a domain name 

nslookup OPTIONS DOMAIN_NAME SERVER

OPTIONS contains the query type as shown in the table below.
DOMAIN_NAME is the domain name you are looking up.
SERVER is the DNS server that you want to query.

For example 

- `nslookup -type=A tryhackme.com 1.1.1.1` (or nslookup -type=a tryhackme.com 1.1.1.1 as it is case-insensitive) can be used to return all the IPv4 addresses used by tryhackme.com.

- Let’s say you want to learn about the email servers and configurations for a particular domain. You can issue `nslookup -type=MX tryhackme.com`

we notice that when a mail server tries to deliver email @tryhackme.com, it will try to connect to the aspmx.l.google.com, which has order 1. If it is busy or unavailable, the mail server will attempt to connect to the next in order mail exchange servers, alt1.aspmx.l.google.com or alt2.aspmx.l.google.com.

`Query type` 	    `Result`
A 	            IPv4 Addresses
AAAA 	        IPv6 Addresses
CNAME 	        Canonical Name
MX 	            Mail Servers
SOA 	        Start of Authority
TXT 	        TXT Records

3. For more advanced DNS queries and additional functionality, you can use `dig`, the acronym for `“Domain Information Groper,”`

Syntex - dig DOMAIN_NAME TYPE

example `dig tryhackme.com MX`


4. Find all subdomains, If we search `DNSDumpster` for tryhackme.com, we will discover the subdomain `blog.tryhackme.com`, which a typical DNS query cannot provide.

We will search for tryhackme.com on DNSDumpster to give you a glimpse of the expected output. Among the results, we got a list of DNS servers for the domain we are looking up. DNSDumpster also resolved the domain names to IP addresses and even tried to geolocate them. We can also see the MX records; DNSDumpster resolved all five mail exchange servers to their respective IP addresses and provided more information about the owner and location. Finally, we can see TXT records. Practically a single query was enough to retrieve all this information.

https://dnsdumpster.com/