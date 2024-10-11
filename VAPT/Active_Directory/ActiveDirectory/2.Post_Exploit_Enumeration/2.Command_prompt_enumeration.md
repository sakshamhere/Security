




Benefits

- No additional or external tooling is required, and these simple commands are often not monitored for by the Blue team.
- We do not need a GUI to do this enumeration.
    
Drawbacks

- The net commands must be executed from a domain-joined machine. If the machine is not domain-joined, it will default to the WORKGROUP domain.
- The net commands may not show all information. For example, if a user is a member of more than ten groups, not all of these groups will be shown in the output.

1. List all users in the AD domain
`net user /domain`

2. Enumerate more detailed information about a single user account:
`net user zoe.marshall /domain`

3. List Groups of Domain
`net group /domain`

4. Enumerate more details such as membership to a group by specifying the group in the same command:
`net group "Tier 1 Admins" /domain`

5. Enumerate the password policy of the domain
`net accounts /domain`

FULL RANGE  OF NET COMMANDS - https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/net-commands-on-operating-systems


*****************************************************************************************************************************
# `Enumerate Users of Domain`

1. List all users in the AD domain

`net user /domain`

This will return all AD users for us and can be helpful in determining the size of the domain to stage further attacks.  

2. Enumerate more detailed information about a single user account:

`net user zoe.marshall /domain`

If the user is only part of a small number of AD groups, this command will be able to show us group memberships. However, usually, after more than ten group memberships, the command will fail to list them all.


# `Enumerate Groups of Domain`

3. List Groups of Domain

`net group /domain`

4. Enumerate more details such as membership to a group by specifying the group in the same command:

`net group "Tier 1 Admins" /domain`

# `Enumerate the password policy of the domain`

`net accounts /domain`

This will provide us with helpful information such as:

    Length of password history kept. Meaning how many unique passwords must the user provide before they can reuse an old password.
    The lockout threshold for incorrect password attempts and for how long the account will be locked.
    The minimum length of the password.
    The maximum age that passwords are allowed to reach indicating if passwords have to be rotated at a regular interval.

This information can benefit us if we want to stage additional password spraying attacks against the other user accounts that we have now enumerated. It can help us better guess what single passwords we should use in the attack and how many attacks can we run before we risk locking accounts. However, it should be noted that if we perform a blind password spraying attack, we may lock out accounts anyway since we did not check to determine how many attempts that specific account had left before being locked.`

*****************************************************************************************************************************

za\tracey.turner@THMDC C:\Users\tracey.turner>`net user /domain`

User accounts for \\THMDC                                                       
                                                                                
------------------------------------------------------------------------------- 
aaron.conway             aaron.hancock            aaron.harris                  
aaron.johnson            aaron.lewis              aaron.moore                   
aaron.patel              aaron.smith              abbie.joyce                   
abbie.robertson          abbie.taylor             abbie.walker                  
abdul.akht ....
..
..
..


za\tracey.turner@THMDC C:\Users\tracey.turner>`net user zoe.marshall /domain`
User name                    zoe.marshall
Full Name                    Zoe Marshall
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/24/2022 11:06:06 PM
Password expires             Never
Password changeable          2/24/2022 11:06:06 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Internet Access
The command completed successfully.


za\tracey.turner@THMDC C:\Users\tracey.turner>`net group /domain`

Group Accounts for \\THMDC

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*HR Share RW
*Internet Access
*Key Admins
*Protected Users
*Read-only Domain Controllers
*Schema Admins
*Server Admins
*Tier 0 Admins
*Tier 1 Admins
*Tier 2 Admins
The command completed successfully.


za\tracey.turner@THMDC C:\Users\tracey.turner>`net group "Tier 1 Admins" /domain`
Group name     Tier 1 Admins
Comment

Members

-------------------------------------------------------------------------------
t1_arthur.tyler          t1_gary.moss             t1_henry.miller
t1_jill.wallis           t1_joel.stephenson       t1_marian.yates
t1_rosie.bryant
The command completed successfully.


za\tracey.turner@THMDC C:\Users\tracey.turner>`net accounts /domain`
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          Unlimited
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        PRIMARY
The command completed successfully.


za\tracey.turner@THMDC C:\Users\tracey.turner>

