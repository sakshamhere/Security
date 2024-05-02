https://www.cloudflare.com/learning/dns/what-is-a-dns-server/

DNS server is which resolved domain name to IP address

There are DNS clients in OS which enables web browsers to connect with DNS servers

# The Resolving process

DNS Clients send request to DNS Resolver , this resolver then behaves as a DNS client itself and sends request to 3 types of DNS Servers in search of right IP.


                                            1. Root Server

DNS Clinet ------> DNS Resolver ---------> 2. TLD Server
                    (recursor)
                                            3. example.com


First Resolver sends request to `Root Server`, The root server then responds to the resolver with the address of a `top-level domain (TLD)` DNS server (such as .com or .net) that stores the information for its domains.

Next the resolver queries the `TLD server`. The TLD server responds with the IP address of the domain’s authoritative `nameserver`.


The resolver then queries the authoritative `nameserver`, which will respond with the IP address of the `origin server`.


The resolver will finally pass the origin server IP address back to the client.


# DNS caching

In addition to the process outlined above, recursive resolvers can also resolve DNS queries using cached data. After retrieving the correct IP address for a given website, the resolver will then store that information in its cache for a limited amount of time. During this time period, if any other clients send requests for that domain name, the resolver can skip the typical DNS lookup process and simply respond to the client with the IP address saved in the cache.

Once the caching time limit expires, the resolver must retrieve the IP address again