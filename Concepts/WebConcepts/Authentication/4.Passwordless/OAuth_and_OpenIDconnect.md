
best video - https://www.youtube.com/watch?v=t18YB3xDfXI

# OAuth
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#oauth

Open Authorization (OAuth) is a protocol that allows an application to authenticate against a server as a user, without requiring passwords or any third party server that acts as an identity provider.

The recommendation is to use and implement OAuth 1.0a or OAuth 2.0 since the very first version (OAuth1.0) has been found to be vulnerable to session fixation.

OAuth 2.0 relies on HTTPS for security and is currently used and implemented by APIs from companies such as Facebook, Google, Twitter and Microsoft. 

OAuth1.0a is more difficult to use because it requires the use of cryptographic libraries for digital signatures. However, since OAuth1.0a does not rely on HTTPS for security, it can be more suited for higher-risk transactions.




    
# OpenID Connect

Oauth 2.0 is designed only for authorization ie for granting access to data and feature from one app to another, OAuth is like giving the client a key. The key is useful but it dosent tell the client who you are and about you.

Opend Id Connect or OIDC is a thin layer that sits on top of Oauth 2.0 and adds functionality of providing information about the person who is logged in ans is requesting the client.\

Open Id enables senerios where one login can be used across multipl applications also known as SSO or Single Sign on

The key diffrence when using Open id is , that when client request for token/auth code, it gets both access token and the Id token

The Id token is specifically formatted string known as JWT

Although JWT and OAuth2 serve different purposes, they are compatible and can be used together. Because the OAuth2 protocol does not specify a token format, JWT can be incorporated into OAuth2 usage.

For example, the access_token returned by the OAuth2 authorization server could be a JWT carrying additional information in the payload. This can improve performance by reducing the round trips required between the resource server and the authentication server. 