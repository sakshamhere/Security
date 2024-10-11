https://stridergearhead.medium.com/ipv6-attack-ad-attack-ea50476dccee

# IPv6 Attacks

We Typically use IPv4, there are chances that we are not even utilising IPv6.

If we look our network adapter we see IPv6 is on.

Now the question is, if we are utilising IPv4 and IPv6 is also on , then who is doing DNS for IPv6??

The answer is nobody!!

`This is loophole something which attacker utilises`

So now we can setup an attack machine, and we will represent as DNS for IPV6 for the messages coming to us in the network


We are going to do this with tool called `Mitm6`

This attack attempts a DNS takeover in a network via IPv6 using `mitm6`, which listens for ipv6 DNS requests, spoofs the DNS reply and passes it to `ntlmrelayx.`


As a result we can relay it to DC and get authentication to Domain Controller

`we can get authentication to DC via LDAP or via SMB`

How??

- For example a machine in network Reboots, and that reboot triggers an event, that event comes to our MITM machine and we can use that to login Domain Controller, and it dosen't have to be an admin on DC

- For example someone in network logins and that NTLM credentials comes to  just like Responder and SMB Relay we saw, and we do whatt called LDAP relay with this credentials towards DC, we login as somain administrator and create an account for us.





# `Mitm6` - this tool help us do all this and will create an account for us on DC

*************************************************************************************************************

1. For this attack firstly we have to install `mitm6` and setup the `LDAPS` (LDAP Secure).

    - go to Server Manager > Manage > Add Roles and features > Next till Server Roles > click on “Active Directory Certificate Services” and add that feature > next till confirmation > click on “Restart the destination server automatically” then hit install.

2. Firstly we will start the `mitm6`.

    - Command: mitm6 -d <domain name>
    - `mitm6` -d marvel.local

3. Now we also have to setup a relay attack, on another tab run `ntlmrelax.py` to setup the relay attack.

    - Command: ntlmrelayx.py -6 -t ldap://<domain controller IP> -wh fakewpad.marvel.local -l lootme
    - `ntlmrelayx.py -6 -t ldaps://192.168.57.140 -wh fakewpad.marvel.local -l lootme`


Now to fast this up, restart any windows machine on network for occurring the event and then we’ll be getting results and it will start dumping data in loot directory. 

Now after admin on that windows machine puts his credetnials after the machine has started ....BOOM!!!

The `Mitm6` logs creates a new user for you in Domain Controller 


# We can do more with `Mitm6`

https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/

******************************************************

# Mitigation

- The obvious mitigation would be to diable IPv6, but it can have some unwanted side effects

So the safest way to prevent `mitm6` is to

- In order to prevent NTLM relaying you should consider disabling it entirely and switch to `Kerberos` or, if that isn’t possible, you should:

    - enable SMB signing to prevent relaying to SMB by requiring all traffic to be signed
    
    - enable LDAP signing to prevent unsigned connections to LDAP

- If WPAD is not in use internally, disable it via Group Policy and by disabling the WinHttpAutoProxySvc service.

- Consider Administrative users to the Protected Users group or marking them as Account is sensitive and cannot be delegated, which will prevent any impersonation of that user via delegation