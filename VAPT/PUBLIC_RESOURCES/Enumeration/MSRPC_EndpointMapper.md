https://0xffsec.com/handbook/services/msrpc/

https://juggernaut-sec.com/ad-recon-msrpc/


First find that MSRPC port open - 135

# Enumeration


# 1. `Querying the RPC locator service with a tool called `rpcdump.py`.`

`rpcdump.py 172.16.1.200 -p 135`

rpcdump.py will query the RPC locator service and will dump endpoints(running services) that utilize the endpoint mapper and are assigned an RPC port number.

The RPC endpoint mapper allows RPC clients to determine the port number currently assigned to a particular RPC service. An endpoint is a protocol port or named pipe on which the server application listens to for client remote procedure calls.


# 2. `Grepping for Interesting Running Services`

Because we are actually seeing services running internally, there are some specific ones we can look for that may provide a potential attack vector. For example, we can check if the print spooler service is running – if it is, we may be able to remotely exploit PrintNightmare and get a SYSTEM shell.

`rpcdump.py 172.16.1.200 -p 135 | egrep 'MS-RPRN|MS-PAR'`


# 3. `Next, we will search for endpoint mappings using a tool called `rpcmap.py`.`

`rpcmap.py 'ncacn_ip_tcp:172.16.1.200'`

Unfortunately, by default on a domain joined Windows 10 machine, we cannot enumerate endpoint mappings anonymously – we are denied access.
However, the same is not always true for Windows Server machines. Oftentimes, by default they do allow anonymous access on the MSRPC level.

Rpcmap.py scans for listening DCE/RPC interfaces and binds to the MGMT interface to get a list of interface UUIDs. If the MGMT interface is not available, it uses a list of known interface UUIDs observed in the wild and tries to bind to each interface. As a result, this tool will identify open DCE/RPC interfaces on a target system.

We were able to anonymously dump endpoint mappings to find listening RPC services as well as their UUID’s.

After getting these services, we can search online to find if any of them are vulnerable to a remote overflow exploit. 

There is a site, here that we can use to reference the UUID values to determine their assignments. Specifically, one that we should be particularly interested in is the RPC interface UUID for `IObjectExporter`, aka the `IOXIDResolver` (used in potato attacks).


# 4. `Retrieving Network Interface IPs Through MSRPC`

Having found the `IObjectExporter` service running, we can use a cool trick to extract the IPs from all of the network interfaces on the host. Extracting the network interfaces may reveal additional networks that can be pivoted to, or it may potentially provide an IPv6 address.

If we discover an IPv6 address, we can use it to try and find additional services on the host to enumerate / exploit.

`./IOXIDResolver.py -t 172.16.1.5`

To do this, we need to use a script that can be found here - https://www.cyber.airbus.com/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/


# 5. `Enumerating Newly Discovered IPv6 Address`

`ping -c 3 2607:fea8:9961:d700:7d6d:b8f1:231e:c614`

`nmap -6 -A -sV -sC -T4 2607:fea8:9961:d700:7d6d:b8f1:231e:c614 -p- -oN tcp_ipv6.nmap`

From here, we would hopefully find a new interesting service running on IPv6 that we did not find when we enumerated the ports running on IPv4.


# Enumerating RPC with Metasploit

For our enumeration, we will focus on the four modules that utilize port 135, which are:

    auxiliary/scanner/dcerpc/endpoint_mapper
    auxiliary/scanner/dcerpc/hidden
    auxiliary/scanner/dcerpc/management
    auxiliary/scanner/dcerpc/tcp_dcerpc_auditor
