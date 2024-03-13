
# OAuth
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#oauth

Open Authorization (OAuth) is a protocol that allows an application to authenticate against a server as a user, without requiring passwords or any third party server that acts as an identity provider.

The recommendation is to use and implement OAuth 1.0a or OAuth 2.0 since the very first version (OAuth1.0) has been found to be vulnerable to session fixation.

OAuth 2.0 relies on HTTPS for security and is currently used and implemented by APIs from companies such as Facebook, Google, Twitter and Microsoft. 

OAuth1.0a is more difficult to use because it requires the use of cryptographic libraries for digital signatures. However, since OAuth1.0a does not rely on HTTPS for security, it can be more suited for higher-risk transactions.



# OpenId
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#openid

OpenId is an HTTP-based protocol that uses identity providers to validate that a user is who they say they are. It is a very simple protocol which allows a service provider initiated way for single sign-on (SSO).

This allows the user to re-use a single identity given to a trusted OpenId identity provider and be the same user in multiple websites, without the need to provide any website with the password, except for the OpenId identity provider.


# SAML
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#saml

Security Assertion Markup Language (SAML) is often considered to compete with OpenId. 

The most recommended version is 2.0 since it is very feature-complete and provides strong security. 

Like OpenId, SAML uses identity providers, but unlike OpenId, it is XML-based and provides more flexibility. SAML is based on browser redirects which send XML data. 

Furthermore, SAML isn't only initiated by a service provider; it can also be initiated from the identity provider. This allows the user to navigate through different portals while still being authenticated without having to do anything, making the process transparent.

While OpenId has taken most of the consumer market, SAML is often the choice for enterprise applications. 

In the past few years, applications like SAP ERP and SharePoint (SharePoint by using Active Directory Federation Services 2.0) have decided to use SAML 2.0 authentication as an often preferred method for single sign-on implementations whenever enterprise federation is required for web services and web applications.