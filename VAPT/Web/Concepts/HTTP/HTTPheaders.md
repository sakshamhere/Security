# what is HTTP header - HTTP headers are used to pass additional information between client and server through the request and response headers

# Request Headers

* Forbidden Header (one which cant be changed programatically)

    - Authorization: <auth-scheme> <authorization-parameters>   - The HTTP Authorization request header can be used to provide credentials that authenticate a user 
                                                                  agent with a server, allowing access to a protected resource.


- HOST                  - the host we are trying to connect
                        Example - google.com

- User-Agent            - specifies the browser client is using, this info is utilized by server how to parse request and what
                          type data to be send
                        Example - Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0

- Accept                - This specifies what kind of data client will accept in regard to file and images
                        Example - text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

- Accept language       - This is the language which browser is reqesting for or which it will accept
                        Example - en-Us

- Accept Encoding       - This specifies the encoding accepted by browser/client
                        Example - gzip, dflate 


- Connection            - It tells the server to close or keep the TCP connection after the request is made
    
    Connection: keep-alive      - tells server that client wants to keep TCP connection alive after recieving response
                                  HTTP 1.1 uses bydefault persistent connnection

    Connection: close           - tells server to close the TCP connection after you send response, 
                                  and it will make new when required  next time)
                                  HTTP 1.o bydefault connection gets closed

- Transfer-encoding     - is a hop-by-hop header, that is applied to a message between two nodes, not to a resource itself. Each 
                          segment of a multi-node connection can use different Transfer-Encoding values. If you want to compress data over the whole connection, use the end-to-end Content-Encoding header instead.

- Content length -       The Content-Length header indicates the size of the message body, in bytes, sent to the recipient.

- Upgrade-Insecure-Requests - 
    1                         Client tells server that if in any case I make a HTTP/unsecure request then I am ready to upgarde 
                              and please send response in HTTPs
    0                         Client is not ready to upgrade

- Cookie                    - The Cookie HTTP request header contains stored HTTP cookies associated with the server 
                              (i.e. previously sent by the server with the Set-Cookie header or set in JavaScript using Document.cookie).

- Referer                   - The Referer HTTP request header contains an absolute or partial address of the page that makes 
                              the request.This header may have undesirable consequences for user security and privacy.

                              The Referer header can contain an origin, path, and querystring, and may not contain URL fragments (i.e. #section) or username:password information. 
                              
                              This has many fairly innocent uses, including analytics, logging, or optimized caching. However, there are more problematic uses such as tracking or stealing information, or even just side effects such as inadvertently leaking sensitive information.

                              The request's referrer policy defines the data that can be included.

- Referrer-Policy           - The Referrer-Policy HTTP header controls how much referrer information (sent with the Referer header) 
                              should be included with requests. Aside from the HTTP header, you can set this policy in HTML.

- X-Forwarded-For           - The X-Forwarded-For (XFF) request header is a de-facto standard header for identifying the originating IP
                              address of a client connecting to a web server through a proxy server.Improper use of this header can be a security risk, This header, by design, exposes privacy-sensitive information, such as the IP address of the client. Therefore the user's privacy must be kept in mind when deploying this header.

- X-Forwarded-Host          - The X-Forwarded-Host (XFH) header is a de-facto standard header for identifying the original 
                              host requested by the client in the Host HTTP request header.

                              Host names and ports of reverse proxies (load balancers, CDNs) may differ from the origin server handling the request, in that case the X-Forwarded-Host header is useful to determine which Host was originally used. This header, by design, exposes privacy-sensitive information, such as the IP address of the client. Therefore the user's privacy must be kept in mind when deploying this header.

                               To avoid the issue of proxy altering the host header, there is another header called X-Forwarded-Host, whose purpose is to contain the original Host header value the proxy received. Most proxies will pass along the original Host header value in the X-Forwarded-Host header. So that header value is likely to be the target origin value you need to compare to the source origin in the Origin or Referer header.

# Response headers

- Server            - tells you the server which is processing the request
                    Example - Apache

- x-Powered-By      - tells you which server side language is processing your request example - PHP

- Content-lenght    - specidies the lenght of message body, so that client knows how much data is sent

- Content-Type      - tells client that I am sending response in this (ex HTTP/txt), as I know you support this by your Accept Header

- Set-Cookie        - The Set-Cookie HTTP response header is used to send a cookie from the server to the user agent, 
                      so that the user agent can send it back to the server later

- Expires           - The Expires HTTP header contains the date/time after which the response is considered expired.

- Access-Control-Allow-Origin   - The Access-Control-Allow-Origin response header indicates whether the response can be shared with 
                                  requesting code from the given origin.

- Access-Control-Allow-Credentials  -  This response header tells client that whether it will allow credentials(cookies,auth tokens 
                                       etc) to share with them

- Content-Security-Policy   - The HTTP Content-Security-Policy response header allows web site administrators to control resources the 
                              user agent is allowed to load for a given page

- HTTP Strict-Transport-Security    -  The HTTP Strict-Transport-Security response header (often abbreviated as HSTS) informs browsers 
                                       that the site should only be accessed using HTTPS, and that any future attempts to access it using HTTP should automatically be converted to HTTPS.

- X-Content-Type-Options        - The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the 
                                  MIME types advertised in the Content-Type headers should be followed and not be changed.

                                  If a response specifies an incorrect content type then browsers may process the response in unexpected ways.

                                  Also if there is no content-type in response the browser starts sniffing no the basis of bytes of content and which leads to attacks.There are security concerns as some MIME types represent executable content.This behavior might lead to otherwise "safe" content such as images being rendered as HTML, enabling cross-site scripting attacks in certain conditions.

                                  For every response containing a message body, the application should include a single Content-type header that correctly and unambiguously states the MIME type of the content in the response body.
                                  
                                  Additionally, the response header "X-content-type-options: nosniff" should be returned in all responses to reduce the likelihood that browsers will interpret content in a way that disregards the Content-type header.

- X-Frame-Options       - The X-Frame-Options HTTP response header can be used to indicate whether or not a browser should be 
                          allowed to render a page in a <frame>, <iframe>, <embed> or <object>. Sites can use this to avoid click-jacking attacks, by ensuring that their content is not embedded into other sites.

- X-XSS-Protection      - The HTTP X-XSS-Protection response header is a feature of Internet Explorer, Chrome and Safari that 
                          stops pages from loading when they detect reflected cross-site scripting (XSS) attacks

* Fetch Metadata Request Headers (provides additional information about the context from which the request originated.)

- Sec-Fetch-Dest        - The Sec-Fetch-Dest fetch metadata request header indicates the request's destination. For example, a request 
                          with an audio destination should request audio data, not some other type of resource (for example, a document that includes sensitive user information).

- Sec-Fetch-User        - The Sec-Fetch-User fetch metadata request header is only sent for requests initiated by user activation, and 
                          its value will always be ?1.

                          The value will always be ?1. When a request is triggered by something other than a user activation, the spec requires browsers to omit the header completely.

                          A server can use this header to identify whether a navigation request from a document, iframe, etc., was originated by the user.


For Example
                        If a user clicks on a page link to another page on the same origin, the resulting request would have the following headers:

                        Sec-Fetch-Dest: document
                        Sec-Fetch-Mode: navigate
                        Sec-Fetch-Site: same-origin
                        Sec-Fetch-User: ?1


# Request and Response header

- Pragma            - Tells the browser not to store the response within the browser cache
    Pragma: no-cache

NOTE - The Expires and Pragma were there before HTTP 1.1, Cache-Control is introduced in HTTP 1.1 and it is the preferred way of caching now

- Cache-Control     - 
    Cache-Control - Private     (It means that the content is set private to user and it will only be cached in client/browser)
    Cache-Control - Public      (If means Cache is public and content can be cached in any proxies ie Proxy server, Reverse Proxy
                                 server)
    Cache-Control - no-store    (This meand content cant be stored/cached, so everytiume client must make request to server for content)
    Cache-Control - no-cache    (This means content can be cached but for client to resue it, he has to re-validate the content
                                 form server)
    Cache-Control - max-age     (The content can be cached for given seconds)


# End-to-end and Hop-by-hop Headers

Headers can also be grouped according to how proxies handle them:

* End-to-end headers - which must be transmitted to the ultimate recipient of a request or response. End-to-end headers in responses    
                       must be stored as part of a cache entry and transmitted in any response formed from a cache entry.

                       These headers must be transmitted to the final recipient of the message: the server for a request, or the client for a response. Intermediate proxies must retransmit these headers unmodified and caches must store them.

* Hop-by-hop headers - which are meaningful only for a single transport-level connection, and are not stored by caches or forwarded by 
                       proxies.

                       These headers are meaningful only for a single transport-level connection, and must not be retransmitted by proxies or cached. Note that only hop-by-hop headers may be set using the Connection header


The following HTTP/1.1 headers are hop-by-hop headers:

Connection
Keep-Alive
Public
Proxy-Authenticate
Transfer-Encoding
Upgrade

All other headers defined by HTTP/1.1 are end-to-end headers.