smtp-brute.nse
smtp-commands.nse
smtp-enum-users.nse
smtp-ntlm-info.nse
smtp-open-relay.nse
smtp-strangeport.nse
smtp-vuln-cve2010-4344.nse
smtp-vuln-cve2011-1720.nse
smtp-vuln-cve2011-1764.nse
                            
msf5 > `search type:auxiliary name:smtp`

Matching Modules
================

   #  Name                                     Disclosure Date  Rank    Check  Description
   -  ----                                     ---------------  ----    -----  -----------
   1  auxiliary/client/smtp/emailer                             normal  No     Generic Emailer (SMTP)
   2  auxiliary/dos/smtp/sendmail_prescan      2003-09-17       normal  No     Sendmail SMTP Address prescan Memory Corruption
   3  auxiliary/fuzzers/smtp/smtp_fuzzer                        normal  Yes    SMTP Simple Fuzzer
   4  auxiliary/scanner/smtp/smtp_enum                          normal  Yes    SMTP User Enumeration Utility
   5  auxiliary/scanner/smtp/smtp_ntlm_domain                   normal  Yes    SMTP NTLM Domain Extraction
   6  auxiliary/scanner/smtp/smtp_relay                         normal  Yes    SMTP Open Relay Detection
   7  auxiliary/scanner/smtp/smtp_version                       normal  Yes    SMTP Banner Grabber
   8  auxiliary/server/capture/smtp                             normal  No     Authentication Capture: SMTP


msf5 > 
************************************************************************************************************************************************************

root@attackdefense:~#` nmap 192.172.28.3 -sV`
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-04 02:16 UTC
Nmap scan report for target-1 (192.172.28.3)
Host is up (0.000010s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
MAC Address: 02:42:C0:AC:1C:03 (Unknown)
Service Info: Host:  openmailbox.xyz

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.51 seconds
root@attackdefense:~# 

msf5 auxiliary(scanner/smtp/smtp_enum) > `run`

[*] 192.172.28.3:25       - 192.172.28.3:25 Banner: 220 openmailbox.xyz ESMTP Postfix: Welcome to our mail server.
[+] 192.172.28.3:25       - 192.172.28.3:25 Users found: , admin, administrator, backup, bin, daemon, games, gnats, irc, list, lp, mail, man, news, nobody, postmaster, proxy, sync, sys, uucp, www-data
[*] 192.172.28.3:25       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/smtp/smtp_enum) >