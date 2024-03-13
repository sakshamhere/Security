# https://developer.mozilla.org/en-US/docs/Web/HTTP

RFC - https://www.rfc-editor.org/rfc/rfc2616#section-8.1.3

# What is HTTP?

-  HTTP (Hyper text transfer protocol) is a stateless application layer protocol which runs on top of TCP.

- It is used for trannsmission of resources like HTML

- designed to communicate between web browsers and web servers, utilizes typical client-server architecture

- data transmitted with HTTP can also be encrypted with TLS (HTTPS)

- HTTP has 2 versions: HTTP 1.0 and HTTP 1.1 (which is typically in use right now)

# HTTP Request

HTTP request are typically made up of following:

- HTTP Version      (the version) 
- HTTP Methods      (GET, POST, OPTIONS, HEAD, PUT, DELETE, specifies what client wants to do)
- Path              (path of file/document that client wants to locate/access)
- HTTP Headers

# HTTP Response

HTTP response are typically made up of following:

- HTTP Version      (the version)
- Status Code       (specifies whether request was successul, 200,300,400,500)
- HTTP Headers

# HTTP Headers

HTTP headers can be easily identified as they contain colons :

- HTTP headers are used by client and server to specify additional information that needs to be sent with an HTTP request or response.

# HTTP Response status code     https://developer.mozilla.org/en-US/docs/Web/HTTP/Status,https://www.rfc-editor.org/rfc/rfc2616#section-8.1.3
Responses are grouped in five classes:

(100–199)   Informational responses 
(200–299)   Successful responses 
(300–399)   Redirection messages 
(400–499)   Client error responses 
(500–599)   Server error responses  

   10.1  Informational 1xx ...........................................57
   10.1.1   100 Continue .............................................58
   10.1.2   101 Switching Protocols ..................................58
   10.2  Successful 2xx ..............................................58
   10.2.1   200 OK ...................................................58
   10.2.2   201 Created ..............................................59
   10.2.3   202 Accepted .............................................59
   10.2.4   203 Non-Authoritative Information ........................59
   10.2.5   204 No Content ...........................................60
   10.2.6   205 Reset Content ........................................60
   10.2.7   206 Partial Content ......................................60
   10.3  Redirection 3xx .............................................61
   10.3.1   300 Multiple Choices .....................................61
   10.3.2   301 Moved Permanently ....................................62
   10.3.3   302 Found ................................................62
   10.3.4   303 See Other ............................................63
   10.3.5   304 Not Modified .........................................63
   10.3.6   305 Use Proxy ............................................64
   10.3.7   306 (Unused) .............................................64



Fielding, et al.            Standards Track                     [Page 3]


RFC 2616                        HTTP/1.1                       June 1999


   10.3.8   307 Temporary Redirect ...................................65
   10.4  Client Error 4xx ............................................65
   10.4.1    400 Bad Request .........................................65
   10.4.2    401 Unauthorized ........................................66
   10.4.3    402 Payment Required ....................................66
   10.4.4    403 Forbidden ...........................................66
   10.4.5    404 Not Found ...........................................66
   10.4.6    405 Method Not Allowed ..................................66
   10.4.7    406 Not Acceptable ......................................67
   10.4.8    407 Proxy Authentication Required .......................67
   10.4.9    408 Request Timeout .....................................67
   10.4.10   409 Conflict ............................................67
   10.4.11   410 Gone ................................................68
   10.4.12   411 Length Required .....................................68
   10.4.13   412 Precondition Failed .................................68
   10.4.14   413 Request Entity Too Large ............................69
   10.4.15   414 Request-URI Too Long ................................69
   10.4.16   415 Unsupported Media Type ..............................69
   10.4.17   416 Requested Range Not Satisfiable .....................69
   10.4.18   417 Expectation Failed ..................................70
   10.5  Server Error 5xx ............................................70
   10.5.1   500 Internal Server Error ................................70
   10.5.2   501 Not Implemented ......................................70
   10.5.3   502 Bad Gateway ..........................................70
   10.5.4   503 Service Unavailable ..................................70
   10.5.5   504 Gateway Timeout ......................................71
   10.5.6   505 HTTP Version Not Supported ...........................71
# HTTP methods

- GET     https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/GET
          To request for data

- POST    To send data to server, Create a new resource

- PUT     Update an existing resource

- PATCH   Partially update an existing resource

- Delete    The HTTP DELETE request method deletes the specified resource.

- TRACE     The HTTP TRACE method performs a message loop-back test along the path to the target resource, 
            providing a useful debugging mechanism

            ie Trace method allows clinet to see what is being recieved at server, or instructs the server to reflect recieved message back to the client

- OPTIONS   The HTTP OPTIONS method requests permitted communication METHODS AVAILIBLE for a given URL or server.

# Some methods

- History.pushState()   - In an HTML document, the history.pushState() method adds an entry to the browser's session history 
                          stack.

    Syntax
                pushState(state, unused)
                pushState(state, unused, url)

    https://developer.mozilla.org/en-US/docs/Web/API/History/pushState


# HTTP Authentication

* HTTP Basic Authentication

Basic authentication is a very simple authentication scheme that is built into the HTTP protocol. The client sends HTTP requests with the Authorization header that contains the Basic word followed by a space and a base64-encoded username:password string. For example, a header containing the demo / p@55w0rd credentials would be encoded as:

Authorization: Basic ZGVtbzpwQDU1dzByZA==

Note: Because base64 is easily decoded, Basic authentication should only be used together with other security mechanisms such as HTTPS/SSL.

https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication

* Access using credentials in the URL

https://username:password@www.example.com/


https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication#access_using_credentials_in_the_url



* Fragment Identifier
https://blog.httpwatch.com/2011/03/01/6-things-you-should-know-about-fragment-urls/
