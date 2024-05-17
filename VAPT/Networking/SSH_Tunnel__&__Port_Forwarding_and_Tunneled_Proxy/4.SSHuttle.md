https://github.com/sshuttle/sshuttle
https://tryhackme.com/r/room/wreath

# `sshuttle `

It doesn't perform a port forward, and the proxy it creates is nothing like the ones we have already seen above

In short, it simulates a VPN, allowing us to route our traffic through the proxy `without using any additional tool like proxychains or other`

Limitations/Requireents
 
- It need Access to the compromised server via `SSH`

- `Python` also needs to be installed on the server

- sshuttle only works on Linux targets.

- we can’t ping or do a SYN Scan through SSHUTTLE similar to proxychains.

First of all we need to install sshuttle. On Kali this is as easy as using the apt package manager:

`sudo apt install sshuttle`


# `Syntex`

- `sshuttle -r username@address subnet`

Rather than specifying subnets, we could also use the `-N` option which attempts to determine them automatically based on the compromised server's own routing table:

- `sshuttle -r username@address -N`

Bear in mind that this may not always be successful though!


Well, that's great, but what happens if we don't have the user's password, or the server only accepts key-based authentication?

Unfortunately, sshuttle doesn't currently seem to have a shorthand for specifying a private key to authenticate to the server with.

However there is a workaround by `--ssh-cmd `switch.
 
So, when using key-based authentication, syntex will be

- `sshuttle -r user@address --ssh-cmd "ssh -i KEYFILE" SUBNET -x compromisedMachineIP`

Finally with `-x` please exclude the compromised machine from this madness, it’s because sometimes accessing the same subnet the compromised machine is in can cause errors


Let's assume a scenario where we've gained control over the `10.200.141.200` and would like to use it as a `pivot` to access a port on another machine `10.200.141.150` to which we can't directly connect from our attacker machine.


    Attacker PC                                         10.200.141.200                                                 10.200.141.150
    (SSH Client)                                         (SSH Server)                                                  (Target Server)
 (Attacker Machine)                                    (Compromised Server)


┌──(kali㉿kali)-[~/Downloads/CVE-2019-15107]
└─$ `sshuttle -r root@10.200.141.200 10.200.141.0/24 --ssh-cmd "ssh -i ssh_key" -x 10.200.141.200`
c : Connected to server.


Now lets run NMAP on Target server


┌──(kali㉿kali)-[~/Downloads]
└─$ `nmap 10.200.141.150 -Pn -n -T4 -sC -sV -sT -p 80,3389,5985`
Starting Nmap 7.93 ( https://nmap.org ) at 2024-04-07 09:19 EDT
Nmap scan report for 10.200.141.150
Host is up (0.0036s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.2.22 ((Win32) mod_ssl/2.2.22 OpenSSL/0.9.8u mod_wsgi/3.3 Python/2.7.2 PHP/5.4.3)
|_http-title: Page not found at /
|_http-server-header: Apache/2.2.22 (Win32) mod_ssl/2.2.22 OpenSSL/0.9.8u mod_wsgi/3.3 Python/2.7.2 PHP/5.4.3
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=git-serv
| Not valid before: 2024-04-03T07:14:40
|_Not valid after:  2024-10-03T07:14:40
|_ssl-date: 2024-04-07T13:20:08+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: GIT-SERV
|   NetBIOS_Domain_Name: GIT-SERV
|   NetBIOS_Computer_Name: GIT-SERV
|   DNS_Domain_Name: git-serv
|   DNS_Computer_Name: git-serv
|   Product_Version: 10.0.17763
|_  System_Time: 2024-04-07T13:20:05+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.25 seconds



