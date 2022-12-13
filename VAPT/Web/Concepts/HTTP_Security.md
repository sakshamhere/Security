
# Cookie Security attributes

* Secure    - A cookie with the Secure attribute is only sent to the server with an encrypted request over the HTTPS protocol. 
              It's never sent with unsecured HTTP (except on localhost), which means man-in-the-middle attackers can't access it easily

            However,someone with access to the client's hard disk (or JavaScript if the HttpOnly attribute isn't set) can read and modify the information.

* HttpOnly  - A cookie with the HttpOnly attribute is inaccessible to the JavaScript Document.cookie API; it's only sent to the server.
              This precaution helps mitigate cross-site scripting (XSS) attacks.

* SameSite  - The SameSite attribute lets servers specify whether/when cookies are sent with cross-site requests
              This provides some protection against cross-site request forgery attacks (CSRF). It takes three possible values: Strict, Lax, and None.
              Servers can (and should) set the cookie SameSite attribute to specify whether or not cookies may be sent to third party sites.

# Security HTTP Header

* Content Security Policy   - Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain 
                              types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.

                              The following directive will only allow scripts to be loaded from the same origin as the page itself:

                                  Content-Security-Policy script-src 'self'

                              The following directive will only allow scripts to be loaded from a specific domain:

                                  Content-Security-Policy script-src https://scripts.normal-website.com

* HTTP Strict-Transport-Security (HSTS) -  The HTTP Strict-Transport-Security response header (often abbreviated as HSTS) informs 
                                           browsers that the site should only be accessed using HTTPS, and that any future attempts to access it using HTTP should automatically be converted to HTTPS.

* X-Content-Type-Options        - The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the 
                                  MIME types advertised in the Content-Type headers should be followed and not be changed.

                                  If a response specifies an incorrect content type then browsers may process the response in unexpected ways.

                                  Also if there is no content-type in response the browser starts sniffing no the basis of bytes of content and which leads to attacks.There are security concerns as some MIME types represent executable content.This behavior might lead to otherwise "safe" content such as images being rendered as HTML, enabling cross-site scripting attacks in certain conditions.

                                  For every response containing a message body, the application should include a single Content-type header that correctly and unambiguously states the MIME type of the content in the response body.
                                  
                                  Additionally, the response header "X-content-type-options: nosniff" should be returned in all responses to reduce the likelihood that browsers will interpret content in a way that disregards the Content-type header.
                                  
      "X-content-type-options: nosniff"


* X-Frame-Options       - The X-Frame-Options HTTP response header can be used to indicate whether or not a browser should be allowed 
                          to render a page in a <frame>, <iframe>, <embed> or <object>. 
                          Sites can use this to avoid click-jacking attacks, by ensuring that their content is not embedded into other sites.


* Referrer-Policy       - There are privacy and security risks associated with the Referer HTTP header.
                          This has many fairly innocent uses, including analytics, logging, or optimized caching. 
                          However, there are more problematic uses such as tracking or stealing information, or even just side effects such as inadvertently leaking sensitive information.

                          The Referer header can contain an origin, path, and querystring, and may not contain URL fragments (i.e. #section) or username:password information. The request's referrer policy defines the data that can be included.

                          The Referrer-Policy header on your server to control what information is sent through the Referer header. 

    no-referrer -       The Referer header will be omitted: sent requests do not include any referrer information.
    origin -            Send only the origin in the Referer header. For example, a document at https://example.com/page.html 
                        will send the referrer https://example.com/.

    same-origin -       Send the origin, path, and query string for same-origin requests. Don't send the Referer header for 
                        cross-origin requests.

Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url

HTTP Refrere Leak explained - https://www.youtube.com/watch?v=uDigwNal7GQ 

* X-XSS-Protection      - The HTTP X-XSS-Protection response header is a feature of Internet Explorer, Chrome and Safari that 
                          stops pages from loading when they detect reflected cross-site scripting (XSS) attacks

                          This feature is non-standard and is not on a standards track. Do not use it on production sites 
                          facing the Web: it will not work for every user. There may also be large incompatibilities between implementations and the behavior may change in the future

                          These protections are largely unnecessary in modern browsers when sites implement a strong Content-Security-Policy that disables the use of inline JavaScript ('unsafe-inline').

Syntax
X-XSS-Protection: 0
X-XSS-Protection: 1
X-XSS-Protection: 1; mode=block
X-XSS-Protection: 1; report=<reporting-uri>

        0
        Disables XSS filtering.

        1
        Enables XSS filtering (usually default in browsers). If a cross-site scripting attack is detected, the browser will sanitize the page (remove the unsafe parts).




# Other Defences

* Turn off HTTP TRACE - it’s crucial that you turn off HTTP TRACE support on all web servers. An attacker can steal cookie data via 
                        Javascript even when document.cookie is disabled or not supported by the client.

                        The HTTP TRACE method is designed for diagnostic purposes. If enabled, the web server will respond to requests that use the TRACE method by echoing in its response the exact request that was received.

                        This behavior is often harmless, but occasionally leads to the disclosure of sensitive information such as internal authentication headers appended by reverse proxies. This functionality could historically be used to bypass the HttpOnly cookie flag on cookies, but this is no longer possible in modern web browsers.

