https://tryhackme.com/r/room/wreath

# 1. Enumeration

Our first step when attempting to pivot through a network is to get an idea of what's around us.

There are five possible ways to enumerate a network through a compromised host:

1. Using material found on the machine. 
2. Using pre-installed tools
3. Using statically compiled tools
3. Using scripting techniques
4. Using local tools through a proxy

***********************************************************************************************************************************


1. Using material found on the machine. 
    
    - The hosts file  
        - `cat /etc/hosts` may include static mappings of IP in Linux

        - `C:\Windows\System32\drivers\etc\hosts` may include static mappings of IP in Windows

        - `/etc/resolv.conf` may include list of DNS servers which may be misconfigured to allow something like a `DNS zone transfer attack`

        - `ipconfig /all` On Windows the easiest way to check the DNS servers for an interface is with ipconfig /all

    - ARP cache 
        - `arp -a` can be used to Windows or Linux to check the ARP cache of the machine -- this will show you any IP addresses of hosts that the target has interacted with recently.

***********************************************************************************************************************************


2. Using pre-installed tools

Ideally we want to take advantage of pre-installed tools on the system (Linux systems sometimes have Nmap installed by default, for example). This is an example of Living off the Land (LotL) -- a good way to minimise risk.

***********************************************************************************************************************************


3. Using statically compiled tools

We know that there are 2 types of libraries in any program/tool, `Static` binaries and `Dynamic` binaries

`Dynamic Binaries` (.so files in linux and .dll in windows) are linked to program at run-time, libraries code can be reused between different running applications so they need less space and memory.

`Static Libraries` (.a files) these files are permanently linked with program/tool, so an executable that uses just static libraries is essentially 100% independent of any other code.

In real-world both lib are used typically for a tool/program

`Statically Compiled Tools are benefitial`, the reason is that these will be completely based on Static libraries and hence when we run them on compromised machine they dont need any other resource and can run independently.

So we can get these statically compiled tools from Internet,For example: statically compiled copies of Nmap for different operating systems (along with various other tools) can be found in various places on the internet.
https://github.com/andrew-d/static-binaries
https://github.com/ernw/static-toolbox/releases/download/1.04/nmap-7.80SVN-x86_64-a36a34aa6-portable.zip

***********************************************************************************************************************************


3. Using scripting techniques

For example, the following `Bash one-line`r would `perform a full ping sweep` of the 192.168.1.x network:

`for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done`

`Port scanning` in bash can be done (ideally) entirely natively:

`for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done`

***********************************************************************************************************************************

4. Using local tools through a proxy

Using local tools through a proxy is incredibly slow, so should only be used as a last resort.
This should be an absolute last resort, as scanning through something like `proxychains` is very slow

we'll be looking at two "proxy" tools: `Proxychains` and `FoxyProxy`

When creating a proxy we open up a port on our own attacking machine which is linked to the compromised server, giving us access to the target network. 

Think of this as being something like a tunnel created between a port on our attacking box that comes out inside the target network 

# `Proxychains`

Proxychains can often slow down a connection: performing an nmap scan through it is especially hellish. 

Ideally you should always try to use static tools where possible, and route traffic through proxychains only when required.

Proxychains is a command line tool which is activated by `prepending the command proxychains to other commands`. For example, to proxy netcat  through a proxy, you could use the command:

`proxychains nc 172.16.0.10 23`

Notice that a p`roxy port was not specified` in the above command. This is because proxychains reads its options from a config file. The master config file is located at `/etc/proxychains.conf`.

however, `/etc/proxychains.conf` is actually the last location where proxychains will look for config. The locations (in order) are:

    1. The current directory (i.e. ./proxychains.conf)
    2. ~/.proxychains/proxychains.conf
    3. /etc/proxychains.conf

copy and make changes wherever you want, If you happen to lose or destroy the original master copy of the proxychains config, a replacement can be downloaded from https://raw.githubusercontent.com/haad/proxychains/master/src/proxychains.conf


- Specifically, we are interested in the "ProxyList" section:

        [ProxyList]
        # add proxy here ...
        # meanwhile
        # defaults set to "tor"
        socks4  127.0.0.1 9050

By default there is one proxy set to localhost port 9050 -- this is the default port for a Tor entrypoint, That said, it is not hugely useful to us. 


- There is one other line in the Proxychains configuration that is worth paying attention to, specifically related to the Proxy DNS settings:

        proxy_dns

If performing an Nmap scan through proxychains, this option can cause the scan to hang and ultimately crash. Comment out the proxy_dns line using a hashtag (#) at the start of the line before performing a scan through the proxy! 

Things to note when scanning through proxychains:

    - You can only use TCP scans -- so no UDP or SYN scans. ICMP Echo packets (Ping requests) will also not work through the proxy, so use the  -Pn  switch to prevent Nmap from trying it.
    
    - It will be extremely slow. Try to only use Nmap through a proxy when using the NSE (i.e. use a static binary to see where the open ports/hosts are before proxying a local copy of nmap to use the scripts library).


# ************************************************************************************************************************************************************

# 2. Port Forwarding

