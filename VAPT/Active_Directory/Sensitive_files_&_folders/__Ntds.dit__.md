# Ntds.dit

AD DS data stores stores this sensitive file

Typically When you compromise Domain Controller you grab this file `because this file contains everything that is stores in Active Directory data`

It contains users, groups, objects and most importantly it contains `Password Hashes of users` in that domain

- It is stored by default in `%SystemRoot%\NTDS` folder on all Domain Controllers

- It is accessible only through Domain Controller processess and protocols