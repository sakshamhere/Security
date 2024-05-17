
192.168.100.1 - No open ports

***************************************
192.168.100.50 - Windows

80,135,139,445,3389

80 
WAMPSERVER 
Apache httpd 2.4.51 ((Win64) PHP/7.4.26)
No webdav found
MariaDB port 3307 possiblity, mentioned on /

http://wordpress.local/2022/04/

smb
host: 192.168.100.50   login: admin   password: superman

RDP
WINSERVER-01
Hotfix - 220
No Todo.txt found
No database running on 3307 (maria is on 3306 and mysql is on 3308)
***********************************
192.168.100.51 - Windows
21, 80, 135,139,445,3389

21, FTP

WINSERVER-02
Hotfix - 223

********************************
192.168.100.52 - linux

21,22,80,3306mysql, 139,445 samba, 3389

RDP
[3389][rdp] host: 192.168.100.52   login: Administrator   password: 123456
[3389][rdp] host: 192.168.100.52   login: Administrator   password: 12345
[3389][rdp] host: 192.168.100.52   login: Administrator   password: 123456789
[3389][rdp] host: 192.168.100.52   login: Administrator   password: password

SSH
[22][ssh] host: 192.168.100.52   login: auditor   password: qwertyuiop (esclate to root by find sudo)

Passwords
sayang           (dbadmin)     
qwertyuiop       (auditor) 

mysql is on 3306

Drupal 7.57, 2018-02-21

***********************************
192.168.100.55 - Windows

80,135,139,445,3389,5357,8080

NetBIOS_Domain_Name: WINSERVER-03

[445][smb] host: 192.168.100.55   login: mary   password: hotmama

[445][smb] host: 192.168.100.55   login: Administrator   password: swordfish

meterpreter > hashdump
admin:1011:aad3b435b51404eeaad3b435b51404ee:0f2011271b98907e6d288066567d3319:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:61fb34469b9989b01be4e8630c52eed6:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
lawrence:1009:aad3b435b51404eeaad3b435b51404ee:18aa104784f77431563b1a1b67f6096c:::
mary:1010:aad3b435b51404eeaad3b435b51404ee:11637a16fca11b3604e3e68d5221b3c7:::
student:1008:aad3b435b51404eeaad3b435b51404ee:bd4ca1fbe028f3c5066467a7f6a73b0b:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::

admin  - blanca 

****************************************
192.168.100.63

192.168.100.67


50 80,Apache windows 64 yes - Wordpress, windows server 2012 R2 Standard 6.3
52  80 Ubuntu linux , Apache yes, Syntex, 
user - admin
workday - starttime ?
admin email ?

root/flag.txt - fca8c84090db44a8adedb98d6406e62b
55 - 80, IISyes Windows, WINSERVER-03
51 - 80, IIS Windows
63. - 80-filtrred linux -freebsd
67 - 80-closed lin, sss-open
5 - 80-closed linux
1 80-filtered No

fca8c84090db44a8adedb98d6406e62b

http://192.168.100.52/drupal/?q=user

http://192.168.100.50/home

WINSERVER - 03
find flag - C:\Users\Administra

*********************************************************************
Drupal Site  http://192.168.100.52/drupal/?q=user
Email of Admin User
User accounts that can be enumerated from SAMBA -3
Vulnerability that can be exploited on drupal site - RCE
CVSS rating for Drupalgeddon2 vulnerability
Flag on server hosting Drupal - /home/auditor/flag.txt - ba3ce1389a7d4c9882e89ea5f357c988
/root/flag.txt - fca8c84090db44a8adedb98d6406e62b
What is root password of MySQL database on server running Drupal - username' => 'drupal' 'password' => 'syntex0421',
What is version of linux kernel running on the system hosting Drupal site - 5.13.0

WINSERVER-03
what vul can be explited to gain access to it (SMB Brute Force, Command Injection, Buffer Overflow, EternalBlue)
What is password of "Administrator" user
What is password of "mary" user


Wordpress
- what can be exploited to get reverse shell (Arbitiary File Upload, RCE, Command inj, SQL inj
Password of "admin" user account on wordpress - estrella 
wordpress file that contains databse configuration (wp-config.php, phpconfig.php, config.php, wp-admin.php) - config.php
How many plugins installed on wordpress site - 3

Which host can be used to Pivot into internal network
(WINSERVER -01, WINDSERVER-03, WINSERVER-02, WEBSERVER-01)

Internal Network
How many host that exist in internal network (2,3,4,5)
Subnet of internal network (192.168.200.0/24, 192.168.0.0/24, 1.0/24, 2.0/24) - 192.168.0.0
Vulnerable web app running on Linux server in internal network

Flag on Winserver-03 C:\Users\Administrator\flag.txt - 5d0005f7796b47c5ad9492b35985063a

Webserver that contains file called "todo.txt" (WINSERVER -02, WINSERVER -01, WEBSERVER-01, WINSERVER -03) - file found on Drupal

how many Hotfixes installed on WINSERVER-01 - 220

Host Vulnerable to SSH-bruteforce (52/50/51/54)

What host on the Internal network contains user called "lawrence"
Find password of user "lawrence" 

Host Running database server on port 3307 on DMZ

Which host on DMZ running web server with WebDav enabled - 192.168.100.51, WINSERVER-02

Hashing algo used for account password in both Linux Servers - Sha512 on .52

