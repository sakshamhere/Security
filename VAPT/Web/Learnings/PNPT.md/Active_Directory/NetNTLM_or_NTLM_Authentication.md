https://tryhackme.com/r/room/breachingad

# NetNTLM 

`New Technology LAN Manager (NTLM)` is the suite of security protocols used to authenticate users' identities in AD.

`NetNTLM` - NTLM can be used for authentication by using a `challenge-response-based scheme` called `NetNTLM`.

# `How it Works?`

NTLM Authentication allows the application to play the role of a middle man between the client and AD.

All authentication material is forwarded to a Domain Controller in the form of a challenge by application, and if completed successfully, the application will authenticate the user. 

This means that the application is authenticating on behalf of the user and not authenticating the user directly on the application itself.

The is good as This prevents the application from storing AD credentials, which should only be stored on a Domain Controller.


                User                                          Application Server                                          Domain Controller

    1. User sends access request     ---->---->--->                    

                                     <---<----<-----       2. Server sends Challange

    3. User sends Response           ---->---->--->        4. Server sends both Challange and Response   ---->---->--->  5. DC compares both Challange and 
                                                                                                                            Response for Authentication

                                      <---<----<-----       2. Server sends DC's response               <---<----<-----  6. DC Sends response (valid or 
                                                                                                                                               invalid)


This authentication mechanism is heavily used by the services on a internal network. However, services that use NetNTLM can also be exposed to the internet For Example:

- Internally-hosted Exchange (Mail) servers that expose an Outlook Web App (OWA) login portal.
- Remote Desktop Protocol (RDP) service of a server being exposed to the internet.
- Exposed VPN endpoints that were integrated with AD.
- Web applications that are internet-facing and make use of NetNTLM.


For example accessing http://ntlmauth.za.tryhackme.com/ requires NTLM authentication, lets provide username as za.tryhackme.com\test and password as test and observe this in Wireshark

161	    30.364014877	10.50.53.49	10.200.55.201	HTTP	257	GET / HTTP/1.1 
171	    30.518163171	10.200.55.201	10.50.53.49	HTTP	248	HTTP/1.1 401 Unauthorized  (text/html)
1628	415.930992101	10.50.53.49	10.200.55.201	HTTP	323	GET / HTTP/1.1 , NTLMSSP_NEGOTIATE
1634	416.094446639	10.200.55.201	10.50.53.49	HTTP	879	HTTP/1.1 401 Unauthorized , NTLMSSP_CHALLENGE (text/html)
1638	416.105415053	10.50.53.49	10.200.55.201	HTTP	767	GET / HTTP/1.1 , NTLMSSP_AUTH, User: za.tryhackme.com\testuser
1646	416.269441766	10.200.55.201	10.50.53.49	HTTP	248	HTTP/1.1 401 Unauthorized  (text/html)
1788	463.634177719	10.50.53.49	10.200.55.201	HTTP	323	GET / HTTP/1.1 , NTLMSSP_NEGOTIATE
1798	463.790278822	10.200.55.201	10.50.53.49	HTTP	879	HTTP/1.1 401 Unauthorized , NTLMSSP_CHALLENGE (text/html)
1802	463.792291346	10.50.53.49	10.200.55.201	HTTP	755	GET / HTTP/1.1 , NTLMSSP_AUTH, User: za.tryhackme.com\test
1813	463.952705985	10.200.55.201	10.50.53.49	HTTP	248	HTTP/1.1 401 Unauthorized  (text/html)
