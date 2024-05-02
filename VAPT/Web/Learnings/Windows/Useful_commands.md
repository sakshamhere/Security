0. systeminfo

1. Net User
 - net user                                                         (This will give users available)
 - net user <username>                                              (this will give details of user)
 - net user <username> <password>                                   (This will change users password)

2. Whoami /?
 - whoami /priv                                                     (This will give privileges of user)

- `dir`
    - `dir /?`

- `findstr` (this is just like grep in linux)
    - `findstr /?`

- - `systeminfo | findstr "OS"`

- `netsh firewall`
    - `netsh firewall show state`

- `sc`
 SC is a command line program used for communicating with the Service Control Manager and services. 

- `cmdkey`
Creates, displays, and deletes stored user names and passwords. 

********************************************************************************



# Net User

C:\Windows\system32>`net help user`
net help user
The syntax of this command is:

NET USER
[username [password | *] [options]] [/DOMAIN]
         username {password | *} /ADD [options] [/DOMAIN]
         username [/DELETE] [/DOMAIN]
         username [/TIMES:{times | ALL}]
         username [/ACTIVE: {YES | NO}]

NET USER creates and modifies user accounts on computers. When used
without switches, it lists the user accounts for the computer. The
user account information is stored in the user accounts database.

username     Is the name of the user account to add, delete, modify, or
             view. The name of the user account can have as many as
             20 characters.
password     Assigns or changes a password for the user's account.
             A password must satisfy the minimum length set with the
             /MINPWLEN option of the NET ACCOUNTS command. It can have as
             many as 14 characters.
*            Produces a prompt for the password. The password is not
             displayed when you type it at a password prompt.
/DOMAIN      Performs the operation on a domain controller of
             the current domain.
/ADD         Adds a user account to the user accounts database.
/DELETE      Removes a user account from the user accounts database.

Options      Are as follows:

   Options                    Description
      --------------------------------------------------------------------
   /ACTIVE:{YES | NO}         Activates or deactivates the account. If
                              the account is not active, the user cannot
                              access the server. The default is YES.
   /COMMENT:"text"            Provides a descriptive comment about the
                              user's account.  Enclose the text in
                              quotation marks.
   /COUNTRYCODE:nnn           Uses the operating system country/region code
                              to implement the specified language files for
                              a user's help and error messages. A value of
                              0 signifies the default country/region code.
   /EXPIRES:{date | NEVER}    Causes the account to expire if date is
                              set. NEVER sets no time limit on the
                              account. An expiration date is in the
                              form mm/dd/yy(yy). Months can be a number,
                              spelled out, or abbreviated with three
                              letters. Year can be two or four numbers.
                              Use slashes(/) (no spaces) to separate
                              parts of the date.
   /FULLNAME:"name"           Is a user's full name (rather than a
                              username). Enclose the name in quotation
                              marks.
   /HOMEDIR:pathname          Sets the path for the user's home directory.
                              The path must exist.
   /PASSWORDCHG:{YES | NO}    Specifies whether users can change their
                              own password. The default is YES.
   /PASSWORDREQ:{YES | NO}    Specifies whether a user account must have
                              a password. The default is YES.
   /LOGONPASSWORDCHG:{YES|NO} Specifies whether user should change their
                              own password at the next logon.The default is NO.
   /PROFILEPATH[:path]        Sets a path for the user's logon profile.
   /SCRIPTPATH:pathname       Is the location of the user's logon
                              script.
   /TIMES:{times | ALL}       Is the logon hours. TIMES is expressed as
                              day[-day][,day[-day]],time[-time][,time
                              [-time]], limited to 1-hour increments.
                              Days can be spelled out or abbreviated.
                              Hours can be 12- or 24-hour notation. For
                              12-hour notation, use am, pm, a.m., or
                              p.m. ALL means a user can always log on,
                              and a blank value means a user can never
                              log on. Separate day and time entries with
                              a comma, and separate multiple day and time
                              entries with a semicolon.
   /USERCOMMENT:"text"        Lets an administrator add or change the User
                              Comment for the account.
   /WORKSTATIONS:{computername[,...] | *}
                              Lists as many as eight computers from
                              which a user can log on to the network. If
                              /WORKSTATIONS has no list or if the list is *,
                              the user can log on from any computer.

NET HELP command | MORE displays Help one screen at a time.

C:\Windows\system32>


# Whoami /?

C:\Windows\system32>`whoami /?`
whoami /?

WhoAmI has three ways of working: 

Syntax 1:
    WHOAMI [/UPN | /FQDN | /LOGONID]

Syntax 2:
    WHOAMI { [/USER] [/GROUPS] [/CLAIMS] [/PRIV] } [/FO format] [/NH]

Syntax 3:
    WHOAMI /ALL [/FO format] [/NH]

Description:
    This utility can be used to get user name and group information
    along with the respective security identifiers (SID), claims,
    privileges, logon identifier (logon ID) for the current user
    on the local system. I.e. who is the current logged on user?
    If no switch is specified, tool displays the user name in NTLM
    format (domain\username).

Parameter List:
    /UPN                    Displays the user name in User Principal 
                            Name (UPN) format.

    /FQDN                   Displays the user name in Fully Qualified 
                            Distinguished Name (FQDN) format.

    /USER                   Displays information on the current user
                            along with the security identifier (SID).

    /GROUPS                 Displays group membership for current user,
                            type of account, security identifiers (SID)
                            and attributes.

    /CLAIMS                 Displays claims for current user,
                            including claim name, flags, type and values.

    /PRIV                   Displays security privileges of the current
                            user.

    /LOGONID                Displays the logon ID of the current user.

    /ALL                    Displays the current user name, groups 
                            belonged to along with the security 
                            identifiers (SID), claims and privileges for 
                            the current user access token.

    /FO       format        Specifies the output format to be displayed.
                            Valid values are TABLE, LIST, CSV.
                            Column headings are not displayed with CSV
                            format. Default format is TABLE.

    /NH                     Specifies that the column header should not
                            be displayed in the output. This is
                            valid only for TABLE and CSV formats.

    /?                      Displays this help message.

Examples:
    WHOAMI
    WHOAMI /UPN
    WHOAMI /FQDN 
    WHOAMI /LOGONID
    WHOAMI /USER
    WHOAMI /USER /FO LIST
    WHOAMI /USER /FO CSV
    WHOAMI /GROUPS
    WHOAMI /GROUPS /FO CSV /NH
    WHOAMI /CLAIMS
    WHOAMI /CLAIMS /FO LIST
    WHOAMI /PRIV
    WHOAMI /PRIV /FO TABLE
    WHOAMI /USER /GROUPS
    WHOAMI /USER /GROUPS /CLAIMS /PRIV
    WHOAMI /ALL
    WHOAMI /ALL /FO LIST
    WHOAMI /ALL /FO CSV /NH
    WHOAMI /?

C:\Windows\system32>
