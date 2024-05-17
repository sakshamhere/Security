
- getuid

- ps

- upload

- download
 
- getprivs

- sessions

- pgrep

- migrate

- load

- sysinfo

- shell

- pwd, cd, mkdir

# sessions
msf5 post(multi/manage/shell_to_meterpreter) > `sessions -h`
Usage: sessions [options] or sessions [id]

Active session manipulation and interaction.

OPTIONS:

    -C <opt>  Run a Meterpreter Command on the session given with -i, or all
    -K        Terminate all sessions
    -S <opt>  Row search filter.
    -c <opt>  Run a command on the session given with -i, or all
    -d        List all inactive sessions
    -h        Help banner
    -i <opt>  Interact with the supplied session ID
    -k <opt>  Terminate sessions by session ID and/or range
    -l        List all active sessions
    -n <opt>  Name or rename a session by ID
    -q        Quiet mode
    -s <opt>  Run a script or module on the session given with -i, or all
    -t <opt>  Set a response timeout (default: 15)
    -u <opt>  Upgrade a shell to a meterpreter session on many platforms
    -v        List all active sessions in verbose mode
    -x        Show extended information in the session table

Many options allow specifying session ranges using commas and dashes.
For example:  sessions -s checkvm -i 1,3-5  or  sessions -k 1-2,5,6