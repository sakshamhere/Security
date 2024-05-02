
# KRBTGT

Specifically, KRB means Kerberos, and TGT stands for Ticket Granting Ticket.

# Is KRBTGT more secure than NTLM authentication?

Yes. With NTLM authentication, the hashed user password is stored on the client, the DC, and the application server, and an application server would have to coordinate directly with the DC to validate access. It’s everywhere and someone with a tool like `mimikatz` could certainly grab that password from any of those locations and make hay.

With KRBTGT, the hash isn’t stored in memory across as many systems, making the theft of a KRBTGT password much more difficult.

To have full unfettered access, a user would have to gain access to the KDC on the DC and steal the password to create a Golden Ticket