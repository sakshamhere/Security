https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html

└─$ whatis rpcclient
rpcclient (1)        - `tool for executing client side MS-RPC functions`


Usage: rpcclient [OPTION...]
  -c, --command=COMMANDS                 Execute semicolon separated cmds
  -I, --dest-ip=IP                       Specify destination IP address
  -p, --port=PORT                        Specify port number

Help options:
  -?, --help                             Show this help message
      --usage                            Display brief usage message

Common samba options:
  -d, --debuglevel=DEBUGLEVEL            Set debug level
  -s, --configfile=CONFIGFILE            Use alternate configuration file
  -l, --log-basename=LOGFILEBASE         Base name for log files
  -V, --version                          Print version
      --option=name=value                Set smb.conf option from command line

Connection options:
  -O, --socket-options=SOCKETOPTIONS     socket options to use
  -n, --netbiosname=NETBIOSNAME          Primary netbios name
  -W, --workgroup=WORKGROUP              Set the workgroup name
  -i, --scope=SCOPE                      Use this Netbios scope

Authentication options:
  -U, --user=USERNAME                    Set the network username
  -N, --no-pass                          Don't ask for a password
  -k, --kerberos                         Use kerberos (active directory) authentication
  -A, --authentication-file=FILE         Get the credentials from a file
  -S, --signing=on|off|required          Set the client signing state
  -P, --machine-pass                     Use stored machine account password
  -e, --encrypt                          Encrypt SMB transport
  -C, --use-ccache                       Use the winbind ccache for authentication
      --pw-nt-hash                       The supplied password is the NT hash