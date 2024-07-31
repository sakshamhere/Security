
# Active Directory Initial Access

Before we can exploit AD misconfigurations for privilege escalation, lateral movement, and goal execution, you need initial access first. 

You need to acquire an initial set of valid AD credentials. 

# `Techniques to get initial AD credentials`

1. `Brute force NTLM Auth` - password spray users found during OSINT

1. `Responder` - Grabbing NTLM Hashes by LLMNR/NBT-NS Poisoning and then crack them.

2. `SMB Relay` - basically if you can't crack the hash then relay it to other machine

3. `IPv6 Attacks` - we can perform this if required conditions are met

4. `LDAP_Pass_Back_Attacks` 