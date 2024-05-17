
# John the Ripper

Using a program called `John the Ripper` we can specify the format of the hash we wish to crack (md5) the wordlist (rockyou.txt) and the wordlist (hash.txt). Please see the full man page for garnering a more complete understanding of all of the commands you can run with this program.

`John --fomat=raw-md5 --wordlists=rockyou.txt hash.txt`

`John --wordlists=rockyou.txt Combinedfileofhashandpassword.txt (created by undhadow)`

NOTE - Eventually John the Ripper may find the password if it was contained the wordlist. In the real world, you may have to find a larger wordlist with a strong amount of common password/username combinations.

# Example1

┌──(kali㉿kali)-[~]
└─$ `echo "Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::" > hash.txt`
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ `cat hash.txt    `                                                              
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
                                                                                                                                                                                                                                   
┌──(kali㉿kali)-[~]
└─$ `sudo john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`
[sudo] password for kali: 
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
alqfna22         (Jon)     
1g 0:00:00:00 DONE (2023-12-20 07:04) 1.176g/s 12000Kp/s 12000Kc/s 12000KC/s alqui..alpusidi
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
                                                                                                                              
┌──(kali㉿kali)-[~]

# Finally we are able to get password `alqfna22`


# Example2

┌──(kali㉿kali)-[~/tmp]
└─$ `unshadow passwd.txt shadow.txt > crackme.txt`
                                                                                      
┌──(kali㉿kali)-[~/tmp]
└─$ `ls`
crackme.txt  exploit.c  passwd.txt  shadow.txt                                                                                                                                                                                                                                       
┌──(kali㉿kali)-[~/tmp]
└─$ `john --wordlist=/home/kali/rockyou.txt crackme.txt `
Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password1        (karen)     
Password1        (user2)     
test123          (gerryconway)     
3g 0:00:00:15 DONE (2024-01-23 07:32) 0.1915g/s 1127p/s 1585c/s 1585C/s paramedic..ellie123
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                       