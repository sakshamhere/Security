

HTTP Basic is less secure because the username and password credentials are carried by every single request between the client and server and it use Base64 encoding which is very easy to decrypt. In addition credentials dont expire and is they do its not very often.

* IMPACT

With HTTP Basic Auth each web server neds to be able to validate usernames and passowords. This means that is must have a copy of password hashes or it must have access to remote system to validate them. An attacker need only compromise any one of the service endpoints in order to intercept the credentials and potetially re-exploit a given accouint even after a significant period of time has elapsed.

* Remediation

- In a token (session id) based systemm, authentication credentials are collected in HTM form and credentials are passed in HTTPS body and not the HTTPs Headers. Also the credentials are carries only once to acquire a valid session token. The password is not repeateadly send in HTTPs request as in Basic Authentication or a Digest Autothentication

- The attack window for a token-based system is very less as session id is set to expire

- In a token-based system, session management is pretty secure as there is a proper life cycle followed for the session token.

- for these reasons ensure tht a token-based system is used to transport authentication credentials