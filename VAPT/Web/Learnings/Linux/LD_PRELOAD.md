# LD_PRELOAD

BASIC SHORT SUMMARY ANSWER - the linux executbale binaries which we call elf files for example /usr/bin/nano or any other uses dynamically linked program or we can say shared object, this is what we can replace by LD_PRELOAD env variable and put our own program with same name in place, so now when we use this env variavble before executing that binary it will use our malicious code instead of default which it should use.

This is called `Load Time hacking` / `Function hijacking`

https://systemweakness.com/linux-privilege-escalation-with-ld-preload-sudo-a13e0b755ede

https://c0nd4.medium.com/linux-sudo-ld-preload-privilege-escalation-7e1e17d544ec

https://www.baeldung.com/linux/ld_preload-trick-what-is

https://www.secureideas.com/blog/2020/ldpreload-introduction.html

https://axcheron.github.io/playing-with-ld_preload/

# Before LD_PRELOAD lets understand what are libraries static libraries and shared libraries

`LD_PRELOAD trick is a useful technique to influence the linkage of shared libraries and the resolution of symbols (functions) at runtime. `

In brief, a library is a collection of compiled functions. We can make use of these functions in our programs without rewriting the same functionality. This can be achieved by either including the library code in our program (static library) or by linking dynamically at runtime (shared library).

Using static libraries, we can build standalone programs. On the other hand, programs built with a shared library require runtime linker/loader support. For this reason, before executing a program, all required symbols are loaded and the program is prepared for execution.

Using `ldd` command we can see what are the shared libraries the program depend on, for example for a program `/usr/bin/nano`

┌──(kali㉿kali)-[~]
└─$ `ldd /usr/bin/nano`
        linux-vdso.so.1 (0x00007ffda26e3000)
        libncursesw.so.6 => /lib/x86_64-linux-gnu/libncursesw.so.6 (0x00007f7e9a4c8000)
        libtinfo.so.6 => /lib/x86_64-linux-gnu/libtinfo.so.6 (0x00007f7e9a496000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7e9a2b5000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f7e9a2b0000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f7e9a573000)

Lets consider we have an exploit code and we create `elf` or executable file by dynamically and statically linking it

┌──(kali㉿kali)-[~/tmp]
└─$ `ls`
exploit.c
└─$ `gcc exploit.c -o Dynexploit`
└─$ `ls`
Dynexploit  exploit.c
└─$ `gcc -static exploit.c -o Statexploit`
└─$ `ls`
Dynexploit  exploit.c  Statexploit

We can confirm which is dynamic and static by `ldd` and `readelf` command for dynamic it will give shared lib with `lld` and will Type as `DYN` with `readelf`

└─$ `ldd Dynexploit` 
        linux-vdso.so.1 (0x00007fff07d4b000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f68319d4000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f6831cd1000)
└─$ `ldd Statexploit` 
        not a dynamic executable
└─$ `readelf -h Dynexploit` 
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x1170
  Start of program headers:          64 (bytes into file)
  Start of section headers:          14952 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30
└─$ `readelf -h Statexploit `
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 03 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - GNU
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x4015b0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          789392 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         10
  Size of section headers:           64 (bytes)
  Number of section headers:         30
  Section header string table index: 29

# Whats LD_PRELOAD

`LD_PRELOAD` is a powerful and advanced feature in the `Linux dynamic linker` that allows users to preload shared object files into the address space of a process (before it starts executing).

`LD_PRELOAD` is often used for debugging and testing purposes, but it can also be used for malicious purposes, such as injecting malware into processes.

The linker links the libraries in the path provided by LD_PRELOAD for compiling the main file. Once a function is linked, when other instance of same function shows up, older location is ignored and the newer location is used.

# How it works

The LD_PRELOAD environment variable specifies a list of shared object files that the dynamic linker should load before any other shared object files. These shared object files are known as "preload libraries". When a process is executed, the dynamic linker searches for the shared object files specified in LD_PRELOAD and loads them into the process's address space. Any function calls made by the process will be directed to the implementations in the preload library specified in LD_PRELOAD, rather than the implementations in the system libraries or other shared object files.

The dynamic linker can be run either indirectly by running some dynamically linked program or shared object. The programs `ld.`so and `ld-linux.so*` find and load the shared objects (shared libraries) needed by a program, prepare the program to run, and then run it.

imagine that you have some executable such as ls. Naturally, these executables reference structures and call functions, which they would either define themselves or link to from static or shared libraries, such as `libc`. Now, imagine that you could provide your own definitions for the symbols an executable depends on and make the program reference your symbols rather than the original ones – basically injecting your definitions. This is precisely what the LD_PRELOAD trick allows us to do.

# Malicious Usecases

1. `Function Hijacking`

This is one of the most common utilities of LD_PRELOAD.

By having your shared object library loaded before the other libraries, it will search the libraries in the order they are loaded to find it. This happens when the ELF binary that is running calls a function that is to be imported from the shared object libraries such as `libc`.  If there is a function in your shared object library that matches that name, your function will be invoked instead of the real one.



If you set `LD_PRELOAD `to the path of a shared object, that file will be loaded before any other library With `LD_PRELOAD` you can give libraries precedence. So for example to run ls with your special malloc() implementation, do this:

`LD_PRELOAD=/path/to/your_library/malloc.so /bin/ls`

With `LD_PRELOAD` you can give libraries precedence.

by loading these with LD_PRELOAD your malloc will be executed rather than the standard ones.

# /etc/sudoers Environment Variables

By default, only specific environment variables are left unchanged while invoking a command through sudo. These include TERM, `PATH, HOME, MAIL, SHELL, LOGNAME, USER, USERNAME, and SUDO_* variables` as noted in the sudoers manual. This is due to the env_reset setting being enabled by default.

In order to preserve additional environment variables through sudo calls, variables can be added to `env_keep`. `All variables that are included in env_keep will remain unchanged`. If the `LD_PRELOAD` environment variable is added to `env_keep `then a user can specify shared libraries to load before the program is executed through sudo. This is dangerous and can lead to privilege escalation.

# The Exploit

If you’re looking to find a privilege escalation method and the output of sudo -l shows that LD_PRELOAD is added to env_keep as shown below, you are in luck!


