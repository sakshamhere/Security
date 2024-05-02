https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
https://www.offsec.com/metasploit-unleashed/
https://docs.rapid7.com/metasploit/

The Metasploit Framework (MSF) is an excellent tool for pentesters. It contains many built-in exploits for many public vulnerabilities and provides an easy way to use these exploits against vulnerable targets. MSF has many other features, like:

- Running reconnaissance scripts to enumerate remote hosts and compromised targets

- Verification scripts to test the existence of a vulnerability without actually compromising the target

- Meterpreter, which is a great tool to connect to shells and run commands on the compromised targets

- Many post-exploitation and pivoting tools



# Basic commands
https://www.offsec.com/metasploit-unleashed/msfconsole-commands/

- msfconsole    (To run Metasploit, we can use the msfconsole command)

- use exploit name (We found one exploit for this service. We can use it by copying the full name of it and using USE to use it)

- show options      (Before we can run the exploit, we need to configure its options. To view the options available to configure, we can use the show options )

- set option     (Any option with Required set to yes needs to be set for the exploit to work. )

- check (Once we have both options set, we can start the exploitation. However, before we run the script, we can run a check to ensure the server is vulnerable:)

- run / exploit (after check we see the server is indeed vulnerable,  Finally, we can use the run or exploit command to run the exploit)


We can set global variables we dont want to set them for all modules like 

msf6 > `setg RHOSTS 10.5.28.129`
RHOSTS => 10.5.28.129
