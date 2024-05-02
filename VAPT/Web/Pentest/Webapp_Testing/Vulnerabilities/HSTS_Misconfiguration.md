
HTTP Strict Transport Security is a web security policy mechenism whereby web server declares that the complying user agents are to interact with it using only secure HTTP connections.

In addition other features about the TLS certificate are saved in user agent's local database inclusing the server's digital identity stored in certificate. 

HSTS is an IELTF standards track protocol and is selected in RFC 6797. The HSTS Polcy is communicated by server to the user agent via a HTTP response header filed name "Strict-Transport-Policy". HSTS Policy specifies a period during which the user agent shall access the server in a secure-only fashion. It will then reconfigure all HTTP links to HTTPS in addition to storing the digital identity provided in certificate from server in the User agent.


* IMPACT

If Max-age is 0, it diables the policy and instructs the browser to delete the entire HSTS reocrd. When HSTS is misconfigured, it could allow a user agent to establish a connection without validating the identity of destination server.

It also presents a senario that would allow a threat actor to downgrade or redirect to unencrypted communications between the user agent and destination server through a MITM attack senario, In this case attacker can see all communication between victim and destination host.


* Remediation

- Transparently redirect users to this secure connection regardless of how they come to the site by sending a 301 HTTP Response.

- Make sure that all user's sensetive session information uses only secure connection by adding a secure keyword when sestting cookies.

- Send a Strict -Transport-Security header to make sure users always visit the site over HTTPS, and never accidently open a window of opportunity for active network acctakers.