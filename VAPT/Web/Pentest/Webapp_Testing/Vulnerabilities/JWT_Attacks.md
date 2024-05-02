
JWT attacks involve a user sending modified JWTs to the server in order to achieve a malicious goal. Typically, this goal is to bypass authentication and access controls by impersonating another user who has already been authenticated.

This means that if an attacker can successfully modify a JWT, they may be able to escalate their own privileges or impersonate other users.

# Impact

The impact of JWT attacks is usually severe. If an attacker is able to create their own valid tokens with arbitrary values, they may be able to escalate their own privileges or impersonate other users, taking full control of their accounts. 

# How they arise

JWT vulnerabilities typically arise due to flawed JWT handling within the application itself. 

These implementation flaws usually mean that the signature of the JWT is not verified properly. 

This enables an attacker to tamper with the values passed to the application via the token's payload. 

Even if the signature is robustly verified, whether it can truly be trusted relies heavily on the server's secret key remaining a secret. If this key is leaked in some way, or can be guessed or brute-forced, an attacker can generate a valid signature for any arbitrary token, compromising the entire mechanism. 

# Working with JWTs in Burp Suite

 You can use Burp Inspector to view and decode JWTs. You can then use the JWT Editor extension to:

    Generate cryptographic signing keys.
    Edit the JWT.
    Resign the token with a valid signature that corresponds to the edited JWT.

You can follow along with the process below using our JWT authentication bypass via weak signing key lab

# Prevention

- Use an up-to-date library for handling JWTs and make sure your developers fully understand how it works, along with any security implications.

- Make sure that you perform robust signature verification on any JWTs that you receive

- Enforce a strict whitelist of permitted hosts for the jku header

- Make sure that you're not vulnerable to path traversal or SQL injection via the kid header parameter.

- Always set an expiration date for any tokens that you issue.

- Avoid sending tokens in URL parameters where possible

- Include the aud (audience) claim (or similar) to specify the intended recipient of the token. 

- Enable the issuing server to revoke tokens (on logout, for example). 