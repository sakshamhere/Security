# What is mean by Relay Attacks ?

A Relay attack is a type of cyber-attack that involves `intercepting and manipulating the communication between two devices` or systems aiming to deceive them into believing they are in close proximity `to gain unauthorized access or control`. 

This type of cyberattack is `commonly associated with security vulnerabilities in authentication protocols`.

Basically a Realy attack is a type of MITM attack only, The work relay here means to transfer/broadcoast something to another machine
********************************************************************************************************************

# SMB Relay Attack

A SMB relay attack is where an attacker captures a users `NTLM hash` and relays its to another machine on the network.
An Attacker basically performs MITM using tool like (`Responder`) on network and intercepts hash and then relays it to another machine.

Basically Attack is to take hash on one user and relay it on another machine,  now if he is also local admin on that other machine then we got the access to that machine as well, this way we can get shell on that other machine as well

In Active Directory such being local admin is common since everyone can log into many machines within a domain.

# `Prerequisites for Successfull Attack`

1. The main thing required is that `Message Signining` should be disabled. We should have any of the below configuration for SMB :
   
    - SMB Signing enabled but not required
    - SMB Signing disabled

2. The victim user must have local admin access on his machine as well as on the other machine on which we will realy his hash to get access. So on both machines this persone needs to be a local admin, because he needs have access to SAM for us to provide hash and secondly we using that hash or realying that hash on other machine should have him has local admin.

3. You cannot relay credentials to the same machine they were captured from.

NOTE
- By default, all Windows workstations (non-servers) have SMB signing either disabled or not enforced.
- By default, all windows servers have it enforced.


# `Attack Steps`

1. The Attacker Identifies Workstations with SMB Signing disabled or not required

2. 