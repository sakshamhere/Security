

# IP vs Hostnames

Question: `Is there a difference between `dir \\za.tryhackme.com\SYSVOL` and `dir \\<DC IP>\SYSVOL` and why the big fuss about DNS?`

There is quite a difference, and it boils down to the authentication method being used. 

When we provide the hostname (FQDN), network authentication will attempt first to perform Kerberos authentication. Since Kerberos authentication relies on fully qualified domain names (FQDN), because the FQDN of the service is referenced directly in the ticket. 

In Active Directory environments where Kerberos authentication uses hostnames/FQDN embedded in the tickets, if we provide the IP instead, we can force the authentication type to be NTLM. 

NTLM is so heavily integrated into Microsoft products that in most cases it's going to be running side-by-side with Kerberos.

While on the surface, this does not matter to us right now, it is good to understand these slight differences since they can allow you to remain more stealthy during a Red team assessment. 

In some instances, organisations will be monitoring for OverPass- and Pass-The-Hash Attacks. 

Forcing NTLM authentication is a good trick to have in the book to avoid detection in these cases.