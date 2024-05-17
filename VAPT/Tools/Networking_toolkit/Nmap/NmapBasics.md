One of the most commonly used scanning tools is Nmap(Network Mapper).

Let us start with the most basic scan. Suppose that we want to perform a basic scan against a target residing at 10.129.42.253. To do this we should type nmap 10.129.42.253 and hit 

We see that the Nmap scan was completed very quickly. This is because if we don't specify any additional options, Nmap will only scan the 1,000 most common ports by default. The scan output reveals that ports 21, 22, 80, 139, and 445 are available.

Doshi@htb[/htb]$ nmap 10.129.42.253

Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-25 16:07 EST
Nmap scan report for 10.129.42.253
Host is up (0.11s latency).
Not shown: 995 closed ports

PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 2.19 seconds


- Under the PORT heading, it also tells us that these are TCP ports. By default, Nmap will conduct a TCP scan unless specifically requested to perform a UDP scan.

- The STATE heading confirms that these ports are open. Sometimes we will see other ports listed that have a different state, such as filtered. This can happen if a firewall is only allowing access to the ports from specific addresses.

- The SERVICE heading tells us the service's name is typically mapped to the specific port number. However, the default scan will not tell us what is listening on that port. Until we instruct Nmap to interact with the service and attempt to tease out identifying information, it could be another service altogether.

# Flags

https://explainshell.com/explain?cmd=nmap+-sP

- sC                    (We can use the -sC parameter to specify that Nmap scripts should be used to try and obtain more detailed information.)
- sV                    (This will run a service enumeration (-sV) scan against the default top 1,000 ports and only return open ports (--open)
                        The -sV parameter instructs Nmap to perform a version scan. In this scan, Nmap will fingerprint services on the target system and identify the service protocol, application name, and version. There is a VERSION heading, which reports the service version and the operating system if this is possible to identify.)
-sU                     
-sL                     (`List Scan`) .The list scan is a degenerate form of host discovery that simply lists each host of the network(s) specified, without 
                        sending any packets to the target hosts.
-sn                     (`scan no port`) option. This tells nmap to not probe the ports on the devices for now. It will do a lightweight, quick scan.
-sP (                   `Skip port scan`) . This option tells Nmap not to do a port scan after host discovery, and only print out the available hosts that 
                        responded to the scan. 
-sS                     (`SYN Scan`) A TCP SYN scan is a stealth scan used to determine if ports on a target system are open, closed or 
                        filtered. SYN scan is relatively unobtrusive and stealthy, since it never completes TCP connections
-PS                     (TCP SYN ping) If you want Nmap to use TCP SYN ping, you can do so via the option -PS followed by the port number, range,
-PA                     (TCP ACK Ping)this sends a packet with an ACK flag set. You must be running Nmap as a privileged user to be able to accomplisthis.
-PU                     (UDP Ping) we can use UDP to discover if the host is online.
-Pn                     (`no ping`) option. This causes nmap to assume the target device is up and to proceed with the other scans. This can be useful for 
                        devices that don't react as expected and confuse nmap into thinking they are off-line.
-PE                     option to enable this echo request behavior. While echo request is the standard ICMP ping query, Nmap does not stop there. In the 
                        normal type of ICMP echo request, a combination of TCP and ACK pings is sent. Using option -PE, the ICMP echo request can be specified as the nmap ping method without coupling TCP ACK ping.
-PR                     (ARP Ping) usage scenarios is to scan an ethernet LAN. On most LANs,When Nmap tries to send a raw IP packet such as an ICMP echo 
                        request, the operating system must determine the destination hardware (ARP) address corresponding to the target IP so that it can properly address the ethernet frame. This is often slow and problematic,ARP scan puts Nmap and its optimized algorithms in charge of ARP requests. And if it gets a response back, Nmap doesn´t even need to worry about the IP-based ping packets since it already knows the host is up. This makes ARP scan much faster and more reliable than IP-based scans. Even if different ping types (such as -PE or -PS) are specified, Nmap uses ARP.
-oG -                   Here we will output the greppable format to stdout with -oG -
- oA                    we will output all scan formats using -oA. This includes XML output, greppable output, and text output that may be useful 
                        to us later.
-n                      (No DNS resolution. This speeds up our scan!)
-R                      Nmap will look up online hosts; however, you can use the option -R to query the DNS server even for offline hosts.
-A                      (aggressive scan) option forces nmap to use operating system detection, version detection, script scanning, and traceroute 
                        detection.
-T                      (timing template) option allows us to specify a value from 0 to 5. This sets one of the timing modes. The timing modes have great 
                        names: paranoid (0), sneaky (1), polite (2), normal (3), aggressive (4), and insane (5). The lower the number, the less impact nmap will have on the bandwidth and other network users.
-p-                     to scan all ports intstead of 1000
-v                      verbose output
--packet-trace          (Trace sent and received packets)
--script                to specify a script (check NSE)
--open                  only return open ports 
--top-ports n           only scan top n ports
--dns-servers 
- oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3, and Grepable format, respectively, to the given filename.

# Basic commands 

- nmap 10.129.42.253                                (gives open ports, nmap will only scan the 1,000 most common ports by default)
- namp -sV 10.129.42.253
- nmap -sC -sV 10.129.42.253
- nmap -sV --script=banner <target>                 (Nmap will attempt to grab the banners We can also attempt this manually using Netcat.Tools 
                                                    like netcat and fscan cannot connect to SSL services in order to grab banners.)
- nmap -p 80 --script http-methods  192.168.46.129  (Nmap will attempt to grab all HTTP methods/verbs availible for target)
- nmap -sC -sV -p21 10.129.42.253



# Nmap Flow
 A Nmap scan usually goes through the steps shown below, although many are optional and depend on the command-line arguments you provide.

Enumerate Targets --> Discover Live Hosts --> Reverse DNS Lookup --> Scan Ports --> Detect Versions --> Detect OS --> Traceroute --> Scripts --> Write Output

# Different approaches that Nmap uses to discover live hosts. In particular, we cover:

`ARP scan`: This scan uses ARP requests to discover live hosts
`ICMP scan`: This scan uses ICMP requests to identify live hosts
`TCP/UDP ping scan`: This scan sends packets to TCP ports and UDP ports to determine live hosts.
