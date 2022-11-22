# https://developer.mozilla.org/en-US/docs/Web/HTTP

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

# HTTP Response status code     https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
Responses are grouped in five classes:

(100–199)   Informational responses 
(200–299)   Successful responses 
(300–399)   Redirection messages 
(400–499)   Client error responses 
(500–599)   Server error responses  

# HTTP methods

- GET     https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/GET
          To request for data

- POST    To send data to server

- PUT     The difference between PUT and POST is that PUT is idempotent: calling it once or several times successively has the same effect (that is no side effect), whereas successive identical POST requests may have additional effects,

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