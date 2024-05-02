https://www.youtube.com/watch?v=XdbSYNhRszE
https://portswigger.net/web-security/request-smuggling

https://github.com/defparam/smuggler

best videos to understand
https://www.youtube.com/watch?v=XC48irGjKNc
https://www.youtube.com/watch?v=C9fi6jlJRBE
https://www.youtube.com/watch?v=7wq2e2nxa38

video by portsiwgger research https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn

# Terminilogy

- `CLRF` - it is nothing but the /r/n which is used in request to say server the this part if is finished here - check video for more -https://www.youtube.com/watch?v=C9fi6jlJRBE

- `HTTP Pipelining` - it is no more used in general, but we can make it used by server. This is basically where we can send multiple request and recieve multiple request check vide - https://www.youtube.com/watch?v=7wq2e2nxa38


HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users. 

Request smuggling vulnerabilities are often critical in nature, allowing an attacker to bypass security controls, gain unauthorized access to sensitive data, and directly compromise other application users

When the front-end server forwards HTTP requests to a back-end server, it typically sends several requests over the same back-end network connection, because this is much more efficient and performant. 

" The protocol is very simple: HTTP requests are sent one after another, and the receiving server parses the HTTP request headers to determine where one request ends and the next one begins "

In this situation, it is crucial that the front-end and back-end systems agree about the boundaries between requests.

Here, the attacker causes part of their front-end request to be interpreted by the back-end server as the start of the next request. This is a request smuggling attack, and it can have devastating results.

# how/why it arise
Most HTTP request smuggling vulnerabilities arise because the HTTP specification provides two different ways to specify where a request ends: the Content-Length header and the Transfer-Encoding header.

Content-Length header - The Content-Length header is straightforward: it specifies the length of the message body in bytes.
Transfer-Encoding     - 

Since the HTTP specification provides two different methods for specifying the length of HTTP messages, it is possible for a single message to use both methods at once, such that they conflict with each other. The HTTP specification attempts to prevent this problem by stating that if both the Content-Length and Transfer-Encoding headers are present, then the Content-Length header should be ignored. This might be sufficient to avoid ambiguity when only a single server is in play, but not when two or more servers are chained together. In this situation, problems can arise for two reasons:

Some servers do not support the Transfer-Encoding header in requests.
Some servers that do support the Transfer-Encoding header can be induced not to process it if the header is obfuscated in some way.
If the front-end and back-end servers behave differently in relation to the (possibly obfuscated) Transfer-Encoding header, then they might disagree about the boundaries between successive requests, leading to request smuggling vulnerabilities.


# How to Perform

The exact way in which this is done depends on the behavior of the two servers:

`CL.TE`: the front-end server uses the Content-Length header and the back-end server uses the Transfer-Encoding header.
`TE.CL`: the front-end server uses the Transfer-Encoding header and the back-end server uses the Content-Length header.
`TE.TE`: the front-end and back-end servers both support the Transfer-Encoding header, but one of the servers can be induced not to process it by obfuscating the header in some way.

`NOTE` - 

1. These techniques are only possible using HTTP/1 requests. Browsers and other clients, including Burp, use HTTP/2 by default to communicate with servers that explicitly advertise support for it via ALPN as part of the TLS handshake. As a result, when testing sites with HTTP/2 support, you need to manually switch protocols in Burp Repeater. You can do this from the Request attributes section of the Inspector panel. 

2. HTTP Request Smuggeling always happens in POST request not in GET request.

# 1. CL.TE vulnerabilities

Example

If The front-end server uses the Content-Length header and the back-end server uses the Transfer-Encoding header. We can perform a simple HTTP request smuggling attack as follows: 

        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 13
        Transfer-Encoding: chunked

        0

        SMUGGLED

The front-end server processes the Content-Length header and determines that the request body is 13 bytes long, up to the end of SMUGGLED. This request is forwarded on to the back-end server.

The back-end server processes the Transfer-Encoding header, and so treats the message body as using chunked encoding. It processes the first chunk, which is stated to be zero length, and so is treated as terminating the request. The following bytes, SMUGGLED, are left unprocessed, and the back-end server will treat these as being the start of the next request in the sequence. 


# 2. TE.CL vulnerabilities

Here, the front-end server uses the Transfer-Encoding header and the back-end server uses the Content-Length header. We can perform a simple HTTP request smuggling attack as follows: 

        POST / HTTP/1.1
        Host: vulnerable-website.com
        Content-Length: 3
        Transfer-Encoding: chunked

        8
        SMUGGLED
        0

The front-end server processes the Transfer-Encoding header, and so treats the message body as using chunked encoding. It processes the first chunk, which is stated to be 8 bytes long, up to the start of the line following SMUGGLED. It processes the second chunk, which is stated to be zero length, and so is treated as terminating the request. This request is forwarded on to the back-end server.

The back-end server processes the Content-Length header and determines that the request body is 3 bytes long, up to the start of the line following 8. The following bytes, starting with SMUGGLED, are left unprocessed, and the back-end server will treat these as being the start of the next request in the sequence. 


NOTE -  To send this request using Burp Repeater, you will first need to go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.
You need to include the trailing sequence \r\n\r\n following the final 0

# 3. TE.TE behavior: obfuscating the TE header

 Here, the front-end and back-end servers both support the Transfer-Encoding header, but one of the servers can be induced not to process it by obfuscating the header in some way.

There are potentially endless ways to obfuscate the Transfer-Encoding header. For example:
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked

Each of these techniques involves a subtle departure from the HTTP specification. Real-world code that implements a protocol specification rarely adheres to it with absolute precision, and it is common for different implementations to tolerate different variations from the specification. To uncover a TE.TE vulnerability, it is necessary to find some variation of the Transfer-Encoding header such that only one of the front-end or back-end servers processes it, while the other server ignores it.

Depending on whether it is the front-end or the back-end server that can be induced not to process the obfuscated Transfer-Encoding header, the remainder of the attack will take the same form as for the CL.TE or TE.CL vulnerabilities already described. 

# Possible Attacks
- Web Cache poisioning
- Web Cache deception
- Session hijacking
- XSS
- Bypassing WAF