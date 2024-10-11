
# Few methods for Active Directory protection against known attacks

1. `Kerberoasting`

Kerberoasting is a common and successful post-exploitation technique for attackers to get privileged access to AD. 

The attacker exploits Kerberos Ticket Granting Service (TGS) to request an encrypted password, and then the attacker cracks it offline through various brute force techniques. 


These attacks are difficult to detect as the request is made through an approved user, and no unusual traffic pattern is generated during this process. 

You can prevent the attack by ensuring an additional layer of authentication through `MFA` or by frequent and periodic Kerberos Key Distribution Centre (KDC) service account password reset

2. `Weak and Easy-to-Guess Passwords`

The best recommendation is to use strong passwords and avoid already known ones.

3. `Brute Forcing RDP`

The intruders or attackers use scanning tools to brute force the weak credentials. Once the brute force is successful, they quickly access the compromised systems and try to do privilege escalation along with a persistent foothold﻿ in the target's computer. 

The best recommendation is to never expose RDP without additional security controls to the public internet.

4. `Publically Accessible Share`

During AD configuration, some share folders are publicly accessible or left unauthenticated, providing an initial foothold for attackers for lateral movement. You can use the `Get-SmbOpenFile` cmdlet in PowerShell to look for any undesired share on the network and configure access accordingly.