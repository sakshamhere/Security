
# MSF Workspace

Workspace allows you to keep track of all your hosts, scans and activities and are extremely useful as they allow you to sort and organize data for multiple peneteration test you perform for diffrent organisations.

MSFconsole allows you to create, manage and switch between workspaces

********************************************************************************************************************************************

msf6 > `workspace -h`
[-] Database not connected
msf6 > 

# First we can chek and make sure postresql is connected, we see its selected but not connected

msf6 > `db_status`
[*] postgresql selected, no connection
msf6 > `services`
[-] Database not connected
msf6 > `exit`

# The connection issue resolved after we re-initialised metasploit db and strated postgresql service

┌──(kali㉿kali)-[~]
└─$ `sudo msfdb init`  
[i] Database already started
[+] Creating database user 'msf'
[+] Creating databases 'msf'
[+] Creating databases 'msf_test'
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
[+] Creating initial database schema

┌──(kali㉿kali)-[~]
└─$ `service postgresql start`
┌──(kali㉿kali)-[~]
└─$ `msfconsole`

msf6 > `db_status`
[*] Connected to msf. Connection type: postgresql.
msf6 > 

# Now lets See about `Workspace`

msf6 > `workspace -h`
Usage:
    workspace          List workspaces
    workspace [name]   Switch workspace

OPTIONS:

    -a, --add <name>          Add a workspace.
    -d, --delete <name>       Delete a workspace.
    -D, --delete-all          Delete all workspaces.
    -h, --help                Help banner.
    -l, --list                List workspaces.
    -r, --rename <old> <new>  Rename a workspace.
    -S, --search <name>       Search for a workspace.
    -v, --list-verbose        List workspaces verbosely.

msf6 > 

# We currently are in `default workspace`
msf6 > `workspace`
* default
msf6 > 

# We can see the data tracked by it, by data we mean hosts and all, since we re-initalised DB data is not there

msf6 > hosts

Hosts
=====

address  mac  name  os_name  os_flavor  os_sp  purpose  info  comments
-------  ---  ----  -------  ---------  -----  -------  ----  --------

# Creating new workspace, and now we are in Test workspace

msf6 > `workspace -a Test`
[*] Added workspace: Test
[*] Workspace: Test
msf6 > `workspace`
  default
* Test
msf6 > 

# We can again switch to default workspace

msf6 > `workspace default`
[*] Workspace: default
msf6 > `workspace`
  Test
* default
msf6 > 
