
# Attributes

1. Secure

Purpose - Secure attribute makes sures that the cookie is sent encrypted over HTTPS protocol (HTTP over TLS) and never sent with HTTP protocol

- Using just HTTPS in web site is not enough, because if a HTTP request is made from browser the cookies will be sent to the target, even if you get redirected later to HTTPs the confientiality is already lost as target already recieved cookies

Risk it Reduces - 

- It makes sure that that cookie is not being stealed via MITM attack, isecure sites.

Key Points

- Insecure `HTTP site cant set` cookies to Secure.

- If cookie is set secure, `browser/user agent will not send this cookie if a HTTP request is made`

- It only `protects Confidentiality not Integrity`, 

    - Although a network attacker can't see the encrypted cookie but he can simply override and forge request using his own cookie to send it to target

    - Cookies with secure attributed can still be modified using client's hard disk or using Javascript

    - Given the fact that a server can't confirm that a cookie was set from a secure origin or even tell where a cookie was originally set, the attacker leverages this and can set his own cookie 

Exceptions - As the site/app insists on HTTPS there is no reason to not to use the secure flag.


HttpOnly exceptions

- If you need javascript to read cookie value

- CSRF mitigation often relies on sending a token value in cookie and expects javascript on client to read it


2. HTTPOnly

Purpose - Httponly attribute makes sure that cookie is not accessbile via client side scripts like javascript

- When browser has cookie with HTTPonly set, if any scripts tries to access that , then browser simply returns an empty string

Risk it reduces

- Majority of XSS attacks targets to steal cookies, httponly prevents that