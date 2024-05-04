FTP

File Transfer Protocol(FTP) is an application layer protocol that moves files between local and remote file systems. It runs on top of TCP, like HTTP. To transfer a file

Why should not be used - https://www.reddit.com/r/sysadmin/comments/2a8pv2/sysadmins_why_would_you_block_ftp_transfers/

Because much like Telnet it's insecure and outdated, there are a million different ways to transfer files, SFTP being one of them. 

FTP is a plain-text protocol. Its literally from 1971. The data and the credentials get sent in plain-text so anyone who can sniff them will have them. Nowadays we use sftp, ftps (rarely), https, etc.

That said, ftp will never die. Its easy to use, everything supports it, etc but some shops are getting rid of it. Also, this block may be part of a larger security initiative. 

but hackers love having an FTP to host their malware, so its targeted a lot

FTP transfers data in cleartext and hence it is banned now.

# SFTP vs FTPS (used rarely) - https://www.youtube.com/watch?v=cvJ3LE_CfkM

* SFTP

- SFTP encrypts both commands and data while in transmission

- Its built on SSH which allows you to securely coonect to remote systems and execute commands

- It supports many diffent encrypyion ciphers, as well as host key verification and passwordless logins with SSH.

* FTPS

- FTPS also known as FTP-SSL is more secure form of FTP

- Its basic FTP with security added to trasnfer coomand and data, uses same commands as FTP but encrypted

PROS of SFTP

- It uses only one port so its easy to use behind a firewall and the connection is protected

- It has more options and can perform more file operations

CONS of FTPS

- It works in operating system that have FTP support but does not have SSH client.

Genrally it is recommeded to use SFTP instead of FTPS if you have options for both,  but both are secure

# basic commands

ftp -p 10.129.42.253



NOTE

- Secure version of FTP is SFTP

- like SSH SFTP is use full public key encryption and is secure even if someone is sniffing network

- FTPS - it is FTP over SSL

- SFTP: The transmission from FTPS through SSH

- "anonymous" is username that is used over FTP when you want to log in without having an account

************************************************************************************************************************************************

# Default Configuration

One of the most used FTP servers on Linux-based distributions is `vsFTPd`. The default configuration of vsFTPd can be found in `/etc/vsftpd.conf`, and some settings are already predefined by default. It is highly recommended to install the vsFTPd server on a VM and have a closer look at this configuration.


# Dangerous Settings

There are many different security-related settings we can make on each FTP server. These can have various purposes, such as testing connections through the firewalls, testing routes, and authentication mechanisms. One of these authentication mechanisms is the anonymous user. This is often used to allow everyone on the internal network to share files and data without accessing each other's computers. With vsFTPd, the optional settings that can be added to the configuration file for the anonymous login look like this:

anonymous_enable=YES 	        Allowing anonymous login?
anon_upload_enable=YES 	        Allowing anonymous to upload files?
anon_mkdir_write_enable=YES 	Allowing anonymous to create new directories?
no_anon_password=YES 	        Do not ask anonymous for password?
anon_root=/home/username/ftp 	Directory for anonymous.
write_enable=YES 	            Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE?

# FTP Users

In addition, there is a file called `/etc/ftpusers` that we also need to pay attention to, as this file is used to deny certain users access to the FTP service. 

In the following example, the users below are not permitted to log in to the FTP service, even if they exist on the Linux system.

┌──(kali㉿kali)-[~]
└─$ `cat /etc/ftpusers`   
# /etc/ftpusers: list of users disallowed FTP access. See ftpusers(5).

root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
nobody
