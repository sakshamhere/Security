https://portswigger.net/research/http2

Although HTTP/2 is complex, it's designed to transmit the same information as HTTP/1.1. 

    HTTP/1.1:

    POST /login HTTP/1.1\r\n
    Host: psres.net\r\n
    User-Agent: burp\r\n
    Content-Length: 9\r\n
    \r\n
    x=123&y=4


    HTTP/2:
    :method	POST
    :path	/login
    :authority	psres.net
    :scheme	https
    user-agent	burp
    x=123&y=4 

Assuming you're already familiar with HTTP/1, there are only three new concepts that you need to understand.

1. `Psudeo Headers`
2. `Binary Protocol`
3. `Message lenght`

1. `Psudeo Headers`

In HTTP/1, the first line of the request contains the request method and path. HTTP/2 replaces the request line with a series of pseudo-headers. 

The five pseudo-headers are easy to recognize as they're represented using a colon at the start of the name:

:method - The request method
:path - The request path. Note that this includes the query string
:authority - The Host header, roughly
:scheme - The request scheme, typically 'http' or 'https'
:status - The response status code - not used in requests

2. `Binary Protocol`

HTTP/1 is a text-based protocol, so requests are parsed using string operations. For example, a server needs to look for a colon in order to know when a header name ends. The potential for ambiguity in this approach is what makes desync attacks possible. 

However HTTP/2 is a binary protocol like TCP, so parsing is based on predefined offsets and much less prone to ambiguity. 

3. `Message lenght`

In HTTP/1, the length of each message body is indicated via the Content-Length or Transfer-Encoding header.

In HTTP/2, those headers are redundant because each message body is composed of data frames which have a built-in length field. 


# Request Smuggling is still possible by Downgrdafin HTTP/2 to HTTP/1


Request Smuggling via HTTP/2 Downgrades

HTTP/2 downgrading is when a front-end server speaks HTTP/2 with clients, but rewrites requests into HTTP/1.1 before forwarding them on to the back-end server. This protocol translation enables a range of attacks, including HTTP request smuggling:

Front-ends speaking HTTP/2 almost always use HTTP/2's built-in message length. However, the back-end receiving a downgraded request doesn't have access to this data, and must use the CL or TE header. This leads to two main types of vulnerability: H2.TE and H2.CL