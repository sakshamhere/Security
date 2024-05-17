https://raw.githubusercontent.com/haad/proxychains/master/src/proxychains.conf

********************************************************************************************************************************************************

# `Assume Senerio`


1. We Compromised 10.200.141.200,  we have SSH credentials/key for it

2. We Discovered another host 10.200.141.150 which is only accessible by 10.200.141.200

3. We Somhow found that there is port 80 open on 10.200.141.200, however we cant access it directly

            A                                               B                                                       C

        10.50.138.14                                 10.200.141.200                                             10.200.141.150
                                                                                                                    80



If we directly try to acces 10.200.141.150:80 from 10.50.138.14, we can't!!

┌──(kali㉿kali)-[~/Downloads/CVE-2019-15107]
└─$ `curl http://10.200.141.150 `                     
^C


Now lets configure Dynamic Port Forwarding

Syntex: 

`ssh -D 1337 -C -N -f user@x.x.x.x`

Here’s a breakdown of the components of that command:

`-D 1337`   — dynamic port forwarding via 1337; (we can use any other port also)
`-C `       — compress all data;
`-N `       — do not execute remote command or shell;
`-f`        — run in background.


┌──(kali㉿kali)-[~/Downloads/CVE-2019-15107]
└─$ `ssh -i ssh_key root@10.200.141.200 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -D 1337 -C -N `              



Now SSH will acts as a `SOCKS proxy`, and will relay all relevant traffic through the SSH connection. Due to this proxy our all network traffic will be going through 10.200.141.200 so now we will be able to access http://10.200.141.150 because it will think the connection is coming from 10.200.141.200 



┌──(kali㉿kali)-[~/Downloads/CVE-2019-15107]
└─$ `curl --socks5 localhost:1337 http://10.200.141.150`

<!DOCTYPE html>
<html lang="en">
<head>
 ....


When we use `-socks5 ` the SOCKS5 sets up proxy for us for that command, but wait this way we will need to specify it everytime, this can be made more easier if we use a tool called `ProxyChains` together with `SOCKS5 proxy`, 

Note `Proxychains` is just a proxy tool to make things easier so that we dont have to set up a proxy for each application by specifying `socks5` in the command

**************************************************************************************************************************************************

# Proxychains

# `Proxychains`

It can be used to proxy data from any application through the tunnel.

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


Edit the configuration file, `/etc/proxychains4.conf`, and give the details of the `SOCKS5 proxy` of the dynamic SSH tunnel.

[ProxyList]
socks5  127.0.0.1 1337

Now we can simply prepend all command with `proxychains`



──(kali㉿kali)-[~/Downloads/CVE-2019-15107]
└─$ `proxychains curl http://10.200.141.150`

[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  10.200.141.150:80  ...  OK

<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <title>Page not found at /</title>
  <meta name="robots" content="NONE,NOARCHIVE">
  <style type=



──(kali㉿kali)-[~/Downloads/CVE-2019-15107]
└─$ `proxychains nmap 10.200.141.0/24 -sn ` 
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.93 ( https://nmap.org ) at 2024-04-04 23:35 EDT
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  10.200.141.1:80 <--socket error or timeout!
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  10.200.141.4:80 <--socket error or timeout!
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  10.200.141.5:80 <--socket error or timeout!
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  10.200.141.6:80 <--socket error or timeout!
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  10.200.141.9:80 <--socket error or timeout!
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  10.200.141.10:80 <--socket error or timeout!
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  10.200.141.11:80 <--socket error or timeout!
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  10.200.141.14:80 <--socket error or timeout!
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
[proxychains] Strict chain  ...  127.0.0.1:1337  ...  10.200.141.15:80 <--socket error or timeout!
RTTVAR has grown to over 2.3

Advise - Never use proxychain for nmap, no results were given

# NOTE - `Proxychains can often slow down a connection: performing an nmap scan through it is especially hellish. Ideally you should try to use static binary tools where possible, and route traffic through proxychains only when required.`