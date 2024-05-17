
`smb-security-mode`


`User-level authentication`: Each user has a separate username/password that is used to log into the system. This is the default setup of pretty much everything these days.

`Share-level authentication`: The anonymous account should be used to log in, then the password is given (in plaintext) when a share is accessed. All users who have access to the share use this password. This was the original way of doing things, but isn't commonly seen, now. If a server uses share-level security, it is vulnerable to sniffing.

`Challenge/response passwords supported`: If enabled, the server can accept any type of password (plaintext, LM and NTLM, and LMv2 and NTLMv2). If it isn't set, the server can only accept plaintext passwords. Most servers are configured to use challenge/response these days. If a server is configured to accept plaintext passwords, it is vulnerable to sniffing. LM and NTLM are fairly secure, although there are some brute-force attacks against them. Additionally, LM and NTLM can fall victim to man-in-the-middle attacks or relay attacks (see MS08-068 or my writeup of it: http://www.skullsecurity.org/blog/?p=110.

`Message signing`: If required, all messages between the client and server must be signed by a shared key, derived from the password and the server challenge. If supported and not required, message signing is negotiated between clients and servers and used if both support and request it. By default, Windows clients don't sign messages, so if message signing isn't required by the server, messages probably won't be signed; additionally, if performing a man-in-the-middle attack, an attacker can negotiate no message signing. If message signing isn't required, the server is vulnerable to man-in-the-middle attacks or SMB-relay attacks.

`smb-enum-domains`

Attempts to enumerate domains on a system, along with their policies. This generally requires credentials, except against Windows 2000. In addition to the actual domain, the "Builtin" domain is generally displayed. Windows returns this in the list of domains, but its policies don't appear to be used anywhere.

Much of the information provided is useful to a penetration tester, because it tells the tester what types of policies to expect. For example, if passwords have a minimum length of 8, the tester can trim his database to match; if the minimum length is 14, the tester will probably start looking for sticky notes on people's monitors.

Another useful piece of information is the password lockouts. A penetration tester often wants to know whether or not there's a risk of negatively impacting a network, and this will indicate it. The SID is displayed, which may be useful in other tools; the users are listed, which uses different functions than smb-enum-users.nse (though likely won't get different results), and the date and time the domain was created may give some insight into its history. 