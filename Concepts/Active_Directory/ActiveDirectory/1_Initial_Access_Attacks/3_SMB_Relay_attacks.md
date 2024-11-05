https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/adversary-in-the-middle/smb-relay#prerequisites

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
   
    - `SMB Signing enabled but not required`
    - `SMB Signing disabled`

2. The victim user must have local admin access on target machine on which we will realy his hash to get access. So on both machines this persone needs to be a local admin, because he needs have access to SAM for us to provide hash and secondly we using that hash or realying that hash on other machine should have him has local admin.

3. You cannot relay credentials to the same machine they were captured from.

NOTE
- By default, all Windows workstations (non-servers) have SMB signing either disabled or not enforced.
- By default, all windows servers have it enforced.


# `Lab Senerio without kali`

In Lab senerio we have 3 machines

1. WS01 (Windows 10 22H2) `(Attacker System)`

2. WS02 (Windows 10 22H2) `(System used to trigger LLMNR)`

3. SRV02 (Windows Server 2019)  ( `Our target, Not a Domain Controller`)

We will be capturing a hash on WS01 using LLMNR Poisoning and performing a SMB relay attack to dump SAM  hashes on SRV02.

As per the prerequisites the user account hash which we will be capturing should be a member of the administrators group on the (SRV02) machine on which we will be relaying to.

# `Lab Senerio with Kali`

Kali Linux (Attacker System)

WS02 (Windows 10 22H2)(System used to trigger LLMNR)

SRV02 (Windows Server 2019)(Not a Domain Controller)

We will be capturing a hash on Kali Linux using LLMNR Poisoning and performing a SMB relay attack to gain shell on SRV02.

As per the prerequisites the user account hash we will be capturing (new.admin) is a member of the administrators group on the machine we will be relaying to (SRV02)

*******************************************************************

# `Attack Steps with kali`

1. Identifying Workstations with SMB Signing disabled or not required

2. Ideally we will use `Responder` for this attack which comes preinstalled on Kali Linux. Before we start Responder we need to make a small change to the configuration file.

    - We need to `turn off SMB and HTTP servers` as `we do not want to respond` to these protocols as `we will be simply capturing the hash` and relaying it to a different tool called `ntlmrelayx.py`

    - `sudo python Responder.py -I eth0 -v`

3. And then call `ntlmrelayx.py` from the Impacket directory.

    - `sudo python ntlmrelayx.py -t [IP] or [CIDR] -smb2support`

Responder has caught the user new.admin attempting to browse to a host that does not exists on the network. After DNS has failed to resolve the machine falls back to LLMNR which in this case we have caught the hash and relayed it over to ntlmrelayx.py.

ntlmrelayx.py then forwards the hash over to the machines specified with the -t switch which in this case is 10.10.10.20 or SRV02.

As the user new.admin is an administrator on SRVS02, ntlmrelayx.py has allowed us to dump the hashes in the SAM database.

We can then takes these hashes and crack them or we can even attempt a pass-the-hash attack and attempt to gain a shell with the NTLMv2 hash on a different machine on the network.

****************************************************************************************

# Gaining Interactive shell instead of hash

1. We can gain Shell using PsExec , using `metasploit psexec module` or manually by `psexec.py` (we can also use Pass the Hash with it)

2. we can also gain shell by ntlmreayx.py by specifying `-i` and knowing the port in output which we can use with netcat to listen


We can gain a shell with the same manner above except this time we speciy the -i switch in ntlmrelayx.py.

  - `sudo python ntlmrelayx.py -t 192.168.64.129 -smb2support -i`

When we get a successful authentication message in ntlmrelayx.py we will need to open a netcat bind shell on the localhost and port specified in the ntlmrelayx.py output.

Start netcat with a localhost address and the port specified in the output above.

`nc 127.0.0.1 <port>`