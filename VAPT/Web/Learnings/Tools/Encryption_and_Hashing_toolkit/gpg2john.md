
# crack encrypted files using john the ripper

Now that you have a basic understanding using gpg, the next question is, what if we do not have the password or key to decrypt the file? How can we crack this. Well, similar to how we brute-forced the hashes with John the Ripper, we can do the same for encrypted files. 

type the following command below to generate the hash for John the Ripper:

`gpg2john [encrypted gpg file] > [filename of the hash you want to create]`

The command above allows us to generate the hash for John the Ripper to understand. Next we can begin the fun part of cracking the encrypted file as seen below:

`john wordlist=[location/name of wordlist] --format=gpg [name of hash we just created]`

┌──(kali㉿kali)-[~]
└─$ ls
Desktop  Documents  Downloads  file1.txt  file1.txt.gpg  hash  Music  Pictures  Public  rockyou.txt  Security  Templates  test  Videos
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ gpg2john file1.txt.gpg > hash                                     

File file1.txt.gpg
                      