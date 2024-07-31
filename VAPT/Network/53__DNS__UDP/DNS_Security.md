
# What happens when DNS servers fail?

DNS servers can fail for multiple reasons, such as power outages, cyber attacks, and hardware malfunctions

In the early days of the Internet, DNS server outages could have a relatively large impact.

Thankfully, today there is a lot of redundancy built into DNS. 

For example, there are many instances of the `root DNS servers` and `TLD nameservers`, and most ISPs have `backup recursive resolvers` for their users. (Individual users can also use `public DNS resolvers, like Cloudflare’s 1.1.1.1, Google's 8.8.8.8`) Most popular websites also have multiple instances of their authoritative nameservers.


In the case of a major DNS server outage, some users may experience delays due to the amount of requests being handled by backup servers, but it would take a DNS outage of very large proportions to make a significant portion of the Internet unavailable. (This actually happened in 2016 when DNS provider Dyn experienced one of the `biggest DDoS attacks in history).` (https://www.cloudflare.com/learning/ddos/famous-ddos-attacks/)