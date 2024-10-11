
# `(LM)` / (LANMAN) Lan Manager Authentication

# `NTLM `  New Technology LAN Manager

# `LDAP `Light Weight Directory Access Protocol


********************************************************************************************************************************************
# (LM) / (LANMAN) Lan Manager Authentication

LAN Manager authentication uses a particularly weak method of hashing a user's password known as the LM hash algorithm, stemming from the mid-1980s when viruses transmitted by floppy disks were the major concern.

# Weakness
Although it is based on DES, a well-studied block cipher, the LM hash has several weaknesses in its design.This makes such hashes crackable in a matter of seconds using rainbow tables, or in a few minutes using brute force. 


Starting with Windows NT, it was replaced by `NTLM,` (`New Technology Lan Manager`)

********************************************************************************************************************************************
# NTLM   New Technology LAN Manager

`NTLM `is the successor to the authentication protocol in Microsoft LAN Manager `(LANMAN)/(LM)`,

Starting with Windows NT, `LM` was replaced by `NTLM`, which is still vulnerable to rainbow tables, and brute force attacks unless long, unpredictable passwords are used, see password cracking. 

NTLM has versions `NTLMv1`, `NTLMv2` and `NTLM2 Session protocols`, each of these is enhanced version of previous version

NLTM is a legacy protocol and was used in Windows Server NT 4 ad below. for windows 2000 and above `Kerberos` is used, it is more secure.

# Weakenss

NTLM remains vulnerable to the pass the hash attack, which is a variant on the reflection attack which was addressed by Microsoft security update MS08-068. 

For example, Metasploit can be used in many cases to obtain credentials from one machine which can be used to gain control of another machine.

********************************************************************************************************************************************
# LDAP Light Weight Directory Access Protocol

LDAP is mainly used for Directory Management and Creation, however It also has authentication and authorisation capabilities but that also in respect to access of directories only.

It is used for Directories-as-a-Service and is the foundation for Microsoft building Activity Directory.

LDAP does not provide the same level of security as `Kerberos`. LDAP does not support encryption by default, which means sensitive information may be transmitted in plain text.



AD maily utilizes `Kerberos` for its authentication ie  Autheticating client/service over a untrusted network.

