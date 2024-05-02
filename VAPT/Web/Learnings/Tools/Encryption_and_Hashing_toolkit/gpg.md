https://www.redhat.com/sysadmin/encryption-decryption-gpg
https://kb.iu.edu/d/awio

# GNU Privacy Guard (GPG or gpg)

The GNU Privacy Guard (GPG or gpg) tool is a native/baseos security tool for encrypting files. According to the gpg man page:

gpg is the OpenPGP (Pretty Good Privacy) part of the GNU Privacy Guard (GnuPG). It is a tool to provide digital encryption and signing services using the OpenPGP standard. gpg features complete key management and all the bells and whistles you would expect from a full OpenPGP implementation.

# Encrypting a File

┌──(kali㉿kali)-[~]
└─$ `echo "This is a sample text" > file1.txt`
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ `gpg -c file1.txt `
gpg: keybox '/home/kali/.gnupg/pubring.kbx' created

`NOTE`  - After this we get a prompt to give a password 

┌──(kali㉿kali)-[~]
└─$ `ls`
Desktop  Documents  Downloads  file1.txt  `file1.txt.gpg`  Music  Pictures  Public  Security  Templates  test  Videos

┌──(kali㉿kali)-[~]
└─$ `cat file1.txt.gpg `                
�       �Ή*�Ge��R�R[;���g9��"3�oa�ҷ�QKݾ1��Ji�����~-!��o
�`�U�_�O���_6�=��1|A��&B�                                                                                                                                                                   

Encrypting a file with gpg leaves the original file intact, file1.txt, and adds the telltale .gpg extension to the newly encrypted file. You should probably remove the original file, file1.txt, so that the encrypted one is the sole source of the information contained in it. Alternatively, if you're going to share the encrypted version, you can rename it before sharing.

The .gpg extension isn't required, but it does let the user know which decryption tool to use to read the file. You can rename the file to anything you want.

┌──(kali㉿kali)-[~]
└─$ `rm file1.txt `

┌──(kali㉿kali)-[~]
└─$ `ls`
`file1.txt.gpg`  Desktop  Documents  Downloads  Music  Pictures  Public  Security  Templates  test  Videos

┌──(kali㉿kali)-[~]
└─$` mv file1.txt.gpg critical_data.doc`
                                                                     
┌──(kali㉿kali)-[~]
└─$ `cat critical_data.doc` 
�       �Ή*�Ge��R�R[;���g9��"3�oa�ҷ�QKݾ1��Ji�����~-!��o
�`�U�_�O���_6�=��1|A��&B�                                                                                                                                                                   

# Decrypting A File

┌──(kali㉿kali)-[~]
└─$ `gpg -d critical_data.doc `
gpg: AES256.CFB encrypted data
gpg: encrypted with 1 passphrase
This is a sample text

# Note that there was no passphrase prompt to decrypt the file. If you want to be prompted to enter the password to decrypt the file again, you'll have to wait ten minutes, which is the default timeout value.

# We can extract content in a file

┌──(kali㉿kali)-[~]
└─$ `gpg critical_data.doc `  
gpg: WARNING: no command supplied.  Trying to guess what you mean ...
gpg: AES256.CFB encrypted data
gpg: encrypted with 1 passphrase
gpg: critical_data.doc: unknown suffix
Enter new filename [file1.txt]: `file1.txt`
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ `ls`
critical_data.doc  Desktop  Documents  Downloads  `file1.txt`  Music  Pictures  Public  Security  Templates  test  Videos
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ 
