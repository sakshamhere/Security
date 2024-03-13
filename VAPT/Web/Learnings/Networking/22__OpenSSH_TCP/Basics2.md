

# Check if SSH is present/installed on machine

┌──(kali㉿kali)-[~]
└─$ `ssh -V`
OpenSSH_9.0p1 Debian-1+b2, OpenSSL 3.0.7 1 Nov 2022
        
# if it dosent retrurn any version we need to install ssh the, `NOTE - in case of Windows we can use PUTTY `

# What is `Dameon`

A Daemon is basically something which constantly runs in background, 

Similary `SSH Daemon` or `sshd` is something which constantly runs and listens for connection

# Now on SSH server , we can check if it is configured to accept SSH connection

# For this we need to check if `SSH Daemon` or `sshd` is running

# If its running/active we can connect to it

┌──(kali㉿kali)-[~]
└─$ `systemctl start ssh.service`
                                                          
┌──(kali㉿kali)-[~]
└─$ `sudo systemctl status ssh`  
● ssh.service - OpenBSD Secure Shell server
     Loaded: loaded (/lib/systemd/system/ssh.service; disabled; preset: disabled)
     Active: active (running) since Fri 2024-02-02 08:40:29 EST; 2s ago
       Docs: man:sshd(8)
             man:sshd_config(5)
    Process: 207637 ExecStartPre=/usr/sbin/sshd -t (code=exited, status=0/SUCCESS)
   Main PID: 207639 (sshd)
      Tasks: 1 (limit: 4615)
     Memory: 1.6M
        CPU: 31ms
     CGroup: /system.slice/ssh.service
             └─207639 "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"

Feb 02 08:40:29 kali systemd[1]: Starting OpenBSD Secure Shell server...
Feb 02 08:40:29 kali sshd[207639]: Server listening on 0.0.0.0 port 22.
Feb 02 08:40:29 kali sshd[207639]: Server listening on :: port 22.
Feb 02 08:40:29 kali systemd[1]: Started OpenBSD Secure Shell server.

