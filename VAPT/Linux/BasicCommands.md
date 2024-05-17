Resources
https://docs.rockylinux.org/books/admin_guide/03-commands/

Command                         Description
Basic commands - `pwd`, `rm`, `mv`, `mkdir`, `rmdir`, `touch`, `cat`, `echo`, `sudo`, `ps`, `whoami`, `su`

- tee                           (Use the tee command to view your output immediately and at the same time, store it for future use.)
- id
- ping
- network statistics (netstat) command
    netstat - a (list all ports), -s(statics by ports), - at (list all TCP ports), -au (all UDP ports)....
- netcat
- nslookup
- host
- ps           (`ps aux`) 
- uname     This is same  as `systeminfo` we use in windows, it gives all system details with diffrent flags
- useradd –d /home/saksham –s /bin/bash saksham (add user)
- usermod (usermod command or modify user)
- ipcalc (provides a simple way to calculate IP information for a host.)
- mkfifo / mknod    (Use `mkfifo` to create named pipe We can use mkfifo or mknod command to create a named pipe.)

- find          (search for files in a directory hierarchy)
- file          (determine file type)
- strings        (print the sequences of printable characters in files) 
- crontab          (gives details on cron jobs)
- Service       (The service command is used to run `System V init scripts`)
- useradd        (adds user)
- ip route       (gives info on IP routes)
- route          (gives info about the IP routing table)   
- lld           (gives the shared libraries /dynamically linked libraries used by elf /executable)
- readelf       (gives details about the elf /executable)
- dpkg          (this is basically Debian Package Manager, its useful to get version of packages installed like nginx)
- function      (allows us to create)
-systemctl      (system control)
******************************************************************************************************************************************
# function
┌──(kali㉿kali)-[~]
└─$ `function demo`
> {
> echo $PATH
> }

┌──(kali㉿kali)-[~]
└─$ `demo `                                                                                     
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games


# uname
root@victim-1:/tmp# `uname --help`
uname --help
Usage: uname [OPTION]...
Print certain system information.  With no OPTION, same as -s.

  -a, --all                print all information, in the following order,
                             except omit -p and -i if unknown:
  -s, --kernel-name        print the kernel name
  -n, --nodename           print the network node hostname
  -r, --kernel-release     print the kernel release
  -v, --kernel-version     print the kernel version
  -m, --machine            print the machine hardware name
  -p, --processor          print the processor type or "unknown"
  -i, --hardware-platform  print the hardware platform or "unknown"
  -o, --operating-system   print the operating system
      --help     display this help and exit
      --version  output version information and exit

GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
Report uname translation bugs to <http://translationproject.org/team/>
Full documentation at: <http://www.gnu.org/software/coreutils/uname>
or available locally via: info '(coreutils) uname invocation'

# ps
root@victim-1:/tmp# `ps aux`
ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0  20044  2872 ?        Ss   05:55   0:00 /bin/bash /root/start.sh
root           8  0.0  0.0 292840 14856 ?        Ss   05:55   0:00 /usr/local/samba/sbin/smbd -D
root           9  0.0  0.0  47076 15816 ?        S    05:55   0:00 /usr/bin/python /usr/bin/supervisord -n
root          10  0.0  0.0 292840  7008 ?        S    05:55   0:00 /usr/local/samba/sbin/smbd -D
root          41  0.0  0.0   4336  1576 ?        S    06:15   0:00 /bin/sh
root          66  0.0  0.0   1152  1028 ?        S    06:23   0:00 /tmp/tnhMY
root          72  0.0  0.0   4336   712 ?        S    06:24   0:00 /bin/sh
root          73  0.0  0.0  20040  2876 ?        S    06:25   0:00 /bin/bash
root          74  0.0  0.0  20224  3320 ?        S    06:25   0:00 /bin/bash -i
root         111  0.0  0.0  17504  2160 ?        R    06:43   0:00 ps aux

# useradd
┌──(kali㉿kali)-[~/Security]
└─$ `useradd --help`
Usage: useradd [options] LOGIN
       useradd -D
       useradd -D [options]

Options:
      --badname                 do not check for bad names
  -b, --base-dir BASE_DIR       base directory for the home directory of the
                                new account
      --btrfs-subvolume-home    use BTRFS subvolume for home directory
  -c, --comment COMMENT         GECOS field of the new account
  -d, --home-dir HOME_DIR       home directory of the new account
  -D, --defaults                print or change default useradd configuration
  -e, --expiredate EXPIRE_DATE  expiration date of the new account
  -f, --inactive INACTIVE       password inactivity period of the new account
  -F, --add-subids-for-system   add entries to sub[ud]id even when adding a system user
  -g, --gid GROUP               name or ID of the primary group of the new
                                account
  -G, --groups GROUPS           list of supplementary groups of the new
                                account
  -h, --help                    display this help message and exit
  -k, --skel SKEL_DIR           use this alternative skeleton directory
  -K, --key KEY=VALUE           override /etc/login.defs defaults
  -l, --no-log-init             do not add the user to the lastlog and
                                faillog databases
  -m, --create-home             create the user's home directory
  -M, --no-create-home          do not create the user's home directory
  -N, --no-user-group           do not create a group with the same name as
                                the user
  -o, --non-unique              allow to create users with duplicate
                                (non-unique) UID
  -p, --password PASSWORD       encrypted password of the new account
  -r, --system                  create a system account
  -R, --root CHROOT_DIR         directory to chroot into
  -P, --prefix PREFIX_DIR       prefix directory where are located the /etc/* files
  -s, --shell SHELL             login shell of the new account
  -u, --uid UID                 user ID of the new account
  -U, --user-group              create a group with the same name as the user
  -Z, --selinux-user SEUSER     use a specific SEUSER for the SELinux user mapping


# tee
The tee command, used with a pipe, reads standard input, then writes the output of a program to standard output and simultaneously copies it into the specified file or files. Use the tee command to view your output immediately and at the same time, store it for future use.

ls -l | tee -a program.ls

# netstat
* The network statistics (netstat) 
command is a networking tool used for troubleshooting and configuration, that can also serve as a monitoring tool for connections over the network. Both incoming and outgoing connections, routing tables, port listening, and usage statistics are common uses for this command. Let's take a look at some of the basic usage for netstat and the most used cases.
https://www.redhat.com/sysadmin/netstat#:~:text=The%20network%20statistics%20(%20netstat%20)%20command,common%20uses%20for%20this%20command.

# ncat
https://www.redhat.com/sysadmin/ncat-security
* The ncat command is part of the nmap suite and was written specifically for it.,Netcat is one of the powerful networking tool, security tool or network monitoring tool. It acts like cat command over a network. It is even considered as a Swiss army knife of networking tools. It is generally used for the following reasons:

Operation related to TCP, UDP or UNIX-domain sockets
Port Scanning
Port listening
Port redirection
open Remote connections
Read/Write data across network
Network debugging
Network daemon testing
Simple TCP proxies
A Socks or HTTP Proxy Command for ssh
https://www.geeksforgeeks.org/practical-uses-of-ncnetcat-command-in-linux/
https://www.redhat.com/sysadmin/ncat-security
https://www.oreilly.com/library/view/practical-web-penetration/9781788624039/a6bdd6aa-c564-4172-9c31-c15ae1a09bd4.xhtml


# nslookup
https://www.computerhope.com/unix/unslooku.htm

# host
https://www.tecmint.com/linux-host-command-examples-for-querying-dns-lookups/

# touch
https://phoenixnap.com/kb/touch-command-in-linux

# cat
https://www.baeldung.com/linux/cat-writing-file

# Env variables
https://owasp.org/www-pdf-archive/Shellshock_-_Tudor_Enache.pdf

- env (list all env variables)
- echo $path (view single)

add your own
- export MYENVVAR="saksham"

# Bash functions

- welcome() {echo "Hi $USER  here is date"; date; } 
- welcome
    Hi kali  here is date
    Thu Feb  9 03:56:43 AM EST 2023

can be defined in env variable

- export welcome='() {echo "Hi $USER  here is date\"; date;}'

NOTE - Shellshock (also called Bashdoor) is a bug that was discovered in the Bash shell in September 2014, allowing the execution of commands through functions stored in the values of environment variables. 

# usermod
https://www.geeksforgeeks.org/usermod-command-in-linux-with-examples/

usermod command or modify user is a command in Linux that is used to change the properties of a user in Linux through the command line. After creating a user we have to sometimes change their attributes like password or login directory etc. so in order to do that we use the Usermod command. The information of a user is stored in the following files: 

    /etc/passwd
    /etc/group
    /etc/shadow
    /etc/login.defs
    /etc/gshadow
    /etc/login.defs

When we execute usermod command in terminal the command make the changes in these files itself. 


# File Permissions

* Finding Files With SUID and SGID Permissions in Linux

https://www.geeksforgeeks.org/finding-files-with-suid-and-sgid-permissions-in-linux/

`SUID(Set-user Identification) and SGID(Set-group identification)` are two special permissions that can be set on executable files, and These permissions allow the file being executed to be executed with the privileges of the owner or the group.

`SUID`: It is special file permission for executable files. This enables other users to run the file with the effective permissions of the file owner. But Instead of normal x which represents executable permissions. We will see s(this indicates SUID) special permission for the user.

`SGID:` This is also special file permission for executable files that enables other users to inherit the effective GID(Group Identifier) of a group owner. Here rather than x which represents executable permissions, we will see s(which indicates SGID) special permission for group users

# mkfifo
https://dev.to/0xbf/use-mkfifo-to-create-named-pipe-linux-tips-5bbk

We can use mkfifo or mknod command to create a named pipe. A pipe is a structure which one end can send message and the other can consume it.

To create a named pipe, we can use mkfifo or mknod

      mkfifo()  makes  a  FIFO  special  file  with  name  pathname.   mode specifies the FIFO's
       permissions.  It is modified by the process's umask in the usual way: the  permissions  of
       the created file are (mode & ~umask).

       A  FIFO  special  file is similar to a pipe, except that it is created in a different way.
       Instead of being an anonymous communications channel, a FIFO special file is entered  into
       the filesystem by calling mkfifo().

       Once you have created a FIFO special file in this way, any process can open it for reading
       or writing, in the same way as an ordinary file.  However, it has to be open at both  ends
       simultaneously before you can proceed to do any input or output operations on it.  Opening
       a FIFO for reading normally blocks until some  other  process  opens  the  same  FIFO  for
       writing, and vice versa.  See fifo(7) for nonblocking handling of FIFO special files