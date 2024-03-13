
For the first time after installing metasploit we need to initialise Metasploit database

┌──(kali㉿kali)-[~]
└─$ `msfdb`     

Manage the metasploit framework database

You can use an specific port number for the
PostgreSQL connection setting the PGPORT variable
in the current shell.

Example: PGPORT=5433 msfdb init

  msfdb init     # start and initialize the database
  msfdb reinit   # delete and reinitialize the database
  msfdb delete   # delete database and stop using it
  msfdb start    # start the database
  msfdb stop     # stop the database
  msfdb status   # check service status
  msfdb run      # start the database and run msfconsole

# Database commands for msfconsole

`db_connect` - This command is used to interact with databases other than the default one

`db_export` - This command is used to export the entire set of data stored in the database for the sake of creating reports or as an input to another tool

`db_nmap` - This command is used for scanning the target with NMAP, and storing the results in the Metasploit database

`db_status`  - This command is used to check whether the database connectivity is present or not

`db_disconnect` - This command is used to disconnect from a particular database

`db_import` - This command is used to import results from other tools such as Nessus, `NMAP`, and so on

`db_rebuild_cache` - This command is used to rebuild the cache if the earlier cache gets corrupted or is stored with older results

# Other Commands

- loot
- notes

**********************************************************************************************************************************************************
# initializing msfdb, check status of msfdb

┌──(kali㉿kali)-[~]
└─$ `sudo msfdb init`  
[i] Database already started
[+] Creating database user 'msf'
[+] Creating databases 'msf'
[+] Creating databases 'msf_test'
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
[+] Creating initial database schema


┌──(kali㉿kali)-[~]
─$ `sudo msfdb status`
● postgresql.service - PostgreSQL RDBMS
     Loaded: loaded (/lib/systemd/system/postgresql.service; disabled; preset: disabled)
     Active: active (exited) since Mon 2024-01-01 10:16:21 EST; 7min ago
    Process: 1523921 ExecStart=/bin/true (code=exited, status=0/SUCCESS)
   Main PID: 1523921 (code=exited, status=0/SUCCESS)
        CPU: 2ms

Jan 01 10:16:21 kali systemd[1]: Starting PostgreSQL RDBMS...
Jan 01 10:16:21 kali systemd[1]: Finished PostgreSQL RDBMS.

COMMAND      PID     USER   FD   TYPE  DEVICE SIZE/OFF NODE NAME
postgres 1523896 postgres    5u  IPv6 3886649      0t0  TCP localhost:5432 (LISTEN)
postgres 1523896 postgres    6u  IPv4 3886650      0t0  TCP localhost:5432 (LISTEN)

UID          PID    PPID  C STIME TTY      STAT   TIME CMD
postgres 1523896       1  0 10:16 ?        Ss     0:00 /usr/lib/postgresql/15/bin/postgres -D /var/lib/postgresql/15/main -c config_file=/etc/postgresql/15/main/postgresql.conf

[+] Detected configuration file (/usr/share/metasploit-framework/config/database.yml)


# checking db status from msfconsole

┌──(kali㉿kali)-[~]
└─$ `service postgresql start && msfconsole`

msf6 > `db_status`
[*] Connected to msf. Connection type: postgresql.
msf6 > 

# Importing Nmap xml output as database

┌──(kali㉿kali)-[~]
└─$ `nmap 44.228.249.3 -p 80 -A -oX Nmapscanresult`

msf6 > `db_import Nmapscanresult`
[*] Importing 'Nmap XML' data
[*] Import: Parsing with 'Nokogiri v1.13.9'
[*] Importing host 44.228.249.3
[*] Successfully imported /home/kali/Nmapscanresult

msf6 > `hosts`

Hosts
=====

address       mac  name                                              os_name  os_flavor  os_sp  purpose  info  comments
-------       ---  ----                                              -------  ---------  -----  -------  ----  --------
44.228.249.3       ec2-44-228-249-3.us-west-2.compute.amazonaws.com  Unknown                    device

msf6 > `services`
Services
========

host          port  proto  name  state  info
----          ----  -----  ----  -----  ----
44.228.249.3  80    tcp    http  open   nginx 1.19.0

msf6 > 

# We could also run nmap from msfconsole and utilise it without importing

msf6 > `db_nmap 44.228.249.4 -p 80 -A`
[*] Nmap: Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-01 12:01 EST
[*] Nmap: Nmap scan report for ec2-44-228-249-3.us-west-2.compute.amazonaws.com (44.228.249.3)
[*] Nmap: Host is up (0.27s latency).
[*] Nmap: PORT   STATE SERVICE VERSION
[*] Nmap: 80/tcp open  http    nginx 1.19.0
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 29.82 seconds

msf6 > `hosts`

Hosts
=====

address       mac  name                                              os_name  os_flavor  os_sp  purpose  info  comments
-------       ---  ----                                              -------  ---------  -----  -------  ----  --------
44.228.249.4       ec2-44-228-249-4.us-west-2.compute.amazonaws.com  Unknown                    device

msf6 > `services`
Services
========

host          port  proto  name  state  info
----          ----  -----  ----  -----  ----
44.228.249.4  80    tcp    http  open   nginx 1.19.0

msf6 > 
