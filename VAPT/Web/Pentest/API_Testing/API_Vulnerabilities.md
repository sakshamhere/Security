
- Verify `X-Content-Type-Options: nosniff` header.
- Verify `X-Frame-Options: deny` header.
- Verify `Content-Security-Policy: default-src 'none'` header.
- Verify use of `HSTS` header
- Verify use of `Basic Auth`.
- Verify unwanted fingerprinting headers - `X-Powered-By`, `Server`, `X-AspNet-Version`, etc.
- Verify `content-type` of response data as you accept and respond with `406 Not Acceptable` response if not matched.
- Verify for proper HTTP method according to the operation: `GET (read)`, `POST (create)`, `PUT/PATCH (replace/update)`, `DELETE (to delete a record)`
- Verify for proper status code according to the operation completed. (`200 OK`, `400 Bad Request`, `401 Unauthorized`, `405 Method Not Allowed`, etc.).
- Verify if `Post` or `Put` is accepted as `Get`.
- Verify CORS configuration (if its allowing to end request with the credentials from the attacker domain)
- Verify CSRF protection (`samesite` cookie)
- Verify sensitive data in the JWT payload, it can be decoded [easily](https://jwt.io/#debugger-io).
- Verify use of any sensitive data (`credentials`, `Passwords`, `security tokens`, or `API keys`) in the URL
- Check if API responses return the entire state of an object rather than the minimum amount of information necessary for users to have.
- Check for Sensetive Information Disclosure (sensitive data like `credentials`, `passwords`, or `security tokens`.)
- API Authentication Vulnerabilies
- API Mass Assignment
- API Rate Limiting
- Verify CORS configuration
- Verify CSRF protection
- Check for Sensetive Information Disclosure
- Check for Privilage Esclation, IDOR
- Check for Parameter Pollution
- Check for Insecure Data Binding
- Check for XSS
- Check for XXE and XML attacks
- Check for JWT Attacks
- Check possible versions (Old versions may be still be in use and be more vulnerable than latest endpoints)

*********************************************************************************************************************************************************

# API Authentication Vulnerabilies
API authentication schemes have unique security requirements as well. 

A holistic API pentest should review how access tokens are generated and revoked, and dive into specific weaknesses of those tokens.

# API Mass Assignment

API Mass Assignment is a condition where a client can overwrite server-side variables that the application should not allow. This is often a high risk vulnerability that can allow users to escalate privileges and manipulate business logic.

# API Rate Limiting
APIs are frequent targets of abuse, especially when intended for public use. Rate limiting has become a vital defense for large API providers to deter bots and other automated attacks.

An API pentest seeks to identify endpoints which may be susceptible to automated attacks and recommend rate limiting accordingly.

Below shows an example response to excessive requests:

HTTP/1.1 429 Too Many Requests
Content-Type: text/html
Retry-After: 3600

# Verify CORS configuration

Cross-Origin Resource Sharing (CORS) is also a common source of misconfigurations. CORS is a specification to relax the same-origin policy enforced by browsers.

Always check the CORS configuration of the API, if its allowing to end request with the credentials from the attacker domain, a lot of damage can be done via CSRF from authenticated victims. 

Care must be taken to ensure that an overly permissive CORS policy does not undermine API security.

# Verify CSRF protection

Cross-Site Request Forgery (CSRF) may also be identified during an API penetration test. Like XSS, a number of behaviors must be reviewed to determine if the finding is valid.

These include behaviors such as:

    - Does the API require JSON? Or can POST parameters be substituted?

    - Is a Content-Type request header such as application/json enforced?

    - Are cookies in use and do they use SameSite properties?

    - Does the application reject malformed JSON?

# Check for Insecure Data Binding

At some point, most API web-based applications will ‘bind’ data. This takes an API response and includes it in the DOM shown on screen to users.

For web-based applications using APIs, data binding methods can be a critical area of security. This also highlights an important relationship that exists between web-based clients and their API.

Let’s compare the safe and dangerous ways to bind the API response for the username "username":"pentest<b>user1</b>":

SAFE -               Welcome pentest<b>user1</b>
Insecure -           Welcome pentestuser1


When APIs store either script or HTML content, the web application must be assessed to determine how this data binds to DOM. 

Although this is rarely considered a vulnerability in the API itself, it is an important relationship that should be analyzed during the pentest.

# Check for Parameter Pollution

/api/account?id=<your account id> → /api/account?id=<your account id>&id=<admin's account id>

# Check for Privilage Esclation

Usually some API endpoints are gong to need more privileges that others. Always try to access the more privileged endpoints from less privileged (unauthorized) accounts to see if it's possible.


`Add parameters`
Something like the following example might get you access to another user’s photo album:

/api/MyPictureList → /api/MyPictureList?user_id=<other_user_id>

`Replace parameters`

You can try to fuzz parameters or use parameters you have seen in a different endpoints to try to access other information
For example, if you see something like: /api/albums?album_id=<album id>
You could replace the album_id parameter with something completely different and potentially get other data: /api/albums?account_id=<account id>

# Check for Sensetive Information Disclosure

- - It’s an easy pitfall for developers to encounter where API responses return the entire state of an object rather than the minimum amount of information necessary for users to have.

- An API pentest should ask questions such as:

    - Should password hashes be disclosed to users?
    - Should users see the locations of other users?


# Check for XSS

Cross-site Scripting (XSS) is a ubiquitous vulnerability on pentest reports. As you might have guessed, this problem is still very relevant to APIs. But things are not so black and white when dealing with an API.

For example, can you tell if the following response indicates an XSS vulnerability?


HTTP/1.1 200 OK
[..]

{"name":"bob<script>alert(1)</script>"}



The answer actually depends on the Content-Type header. If the following Content-Type is set, the API would not be vulnerable:


Content-Type: application/json; charset=utf-8



However, a Content-Type treating the response as HTML would, in fact, be vulnerable:



Content-Type: text/html

# Check for XXS

SOAP / XML api may be vulnerable to XXE but usually DTD Declarations are disallowed in the input from the user.