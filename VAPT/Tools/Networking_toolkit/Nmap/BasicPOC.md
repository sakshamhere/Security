
# Home Wi-fi Network scan to find inexplicable devide if any
https://www.howtogeek.com/423709/how-to-see-all-devices-on-your-network-with-nmap-on-linux/

First turned vmware connection to Bridge instead of NAT - https://www.youtube.com/watch?v=KMm0Xl8g4eM - check description

1. checked ip address subnet using ifonfig

2. ran 

nmap -sP 192.168.46.0/24

3. Then did a deeper scan and for that ran

nmap 192.168.46.0/24

4. Got some devices with some ports open so deciced to do aggressive scan on that device with timing factor 4

nmap -A -T4 192.168.46.111

5. used -pn for devices that didnt gave any open ports

nmap -A -T4 -Pn 192.168.46.111

6. didnt got anything related to mac address till now so used `arp`,  it gave all ip adress with mac adres on the network

arp


We have verified that there are no inexplicable devices on this network.

# Tracing newtwork packet into device discovored
https://www.redhat.com/sysadmin/quick-nmap-inventory

nmap -vv -n -A -T4 -Pn --packet-trace 192.168.29.193 

# Using `NSE Scripts` 

nmap -p443 --script http-waf-detect --script-args="http-waf-detect.aggro,http-waf-detect.detectBodyChanges" www.slimmer.ai

# Using DNS proxies to perform stealth scan on target

By default, Nmap runs an `rDNS (reverse-DNS)` resolution on any responsive host. Let's see if we can gather some information about a specific network and remain anonymous. The anonymous part is because we'll use public DNS servers, namely 8.8.4.4 and 8.8.8.8, to perform the recursive query.

host redhat.com 8.8.8.8   or   dig redhat.com 8.8.8.8

nmap --dns-servers 8.8.4.4,8.8.8.8 -sL 209.132.183.105/24