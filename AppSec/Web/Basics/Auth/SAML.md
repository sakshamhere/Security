
# XXE via SAML

https://hackerone.com/reports/106865

# SAML authentication bypass (XML Signature Wrapping (XSW))

https://hackerone.com/reports/812064

https://hackerone.com/reports/356284

When using SAML authentication, responses are not checked properly. This allows attacker to inject/modify any assertions in the SAML response and thus, for example, authenticate as administrator.


# bypass the signup SAML enforcement

add the %0d%0a in the end of the email parameter

https://hackerone.com/reports/2101076


# Replay attacks (reuse saml assertion)

SAML messages are vulnerable to replay attacks: the attacker intercepts a valid SAML message and uses it to impersonate a legitimate SAML action (like a user signing in). This type of attack is possible if the system does not implement adequate mechanisms to prevent the reuse of SAML messages, such as timestamps.


# Open redirect (modify RelayState parameter)

When an SSO action is initiated by the service provider, the user is directed to the identity provider and forgets about it. The identity provider knows where to send the response using `RelayState`, an HTTP parameter incorporated in both the SAML request and response. To defend against such attacks, confirm the value of the RelayState is a trusted URL before redirection.

https://hackerone.com/reports/171398

# Signature exclusion

If a SAML implementation is not properly implemented, it can skip signature validation entirely or check only the signature in the first assertion of many. Attackers can then bypass those insufficient checks and access your users’ data.