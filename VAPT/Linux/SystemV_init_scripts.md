# System V (`sysV`)

# `Init` 

`Init` is the program on Unix and Linux systems which spawns all other processes. It runs as a daemon and typically has PID 1. It is the `parent of all processes.`

Its primary role is to `create processes from a script` stored in the file `/etc/inittab` file.


All `System V` init scripts are stored in `/etc/rc.d/init.d/` or `/etc/init.d` directory.

These scripts are used to control system startup and shutdown. Usually you will find scripts to start a web server or networking. For example you type the command:

`/etc/init.d/httpd start` or `service httpd start`
OR
`/etc/init.d/network restart` or `service network restart`

All The scripts are typically written in a command interpreter named `/bin/sh` or `/bin/bash `or `/sbin/openrc-run`.

┌──(kali㉿kali)-[~]
└─$ `ls /etc/init.d`    
apache2              bluetooth         dbus        iodined            lm-sensors  nfs-common     openvpn       procps                       rpcbind      screen-cleanup     ssh       udev
apache-htcacheclean  console-setup.sh  dns2tcp     ipsec              mariadb     nginx          pcscd         ptunnel                      rsync        smartmontools      sslh      x11-common
apparmor             cron              haveged     keyboard-setup.sh  miredo      nmbd           plymouth      pulseaudio-enable-autospawn  rwhod        smbd               stunnel4  xl2tpd
atftpd               cryptdisks        hwclock.sh  kmod               mosquitto   ntpsec         plymouth-log  redis-server                 samba-ad-dc  snmpd              sudo
avahi-daemon         cryptdisks-early  inetsim     lightdm            networking  open-vm-tools  postgresql    redsocks                     saned        speech-dispatcher  sysstat

┌──(kali㉿kali)-[~]
└─$ `file /etc/init.d/postgresql`
/etc/init.d/postgresql: POSIX shell script, ASCII text executable


**********************************************************************************************************

We can also create our own `SysV` script and start, stop and restart
To use the script, you would typically place it in the `/etc/init.d/` or `/usr/loca/etc/init.d/` directory and make it executable. Then, you can use commands like service command or "/usr/local/etc/init.d/my-java-app start" to manage the service's startup and shutdown:

`sudo /usr/local/etc/init.d/my-java-app start`

## OR ##

`sudo service my-java-app start`


We can also enable a service to start at system startup by `systemctl`

`sudo systemctl enable postgresql`


