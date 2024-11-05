# Basic Authentication

* It is the most basic form of authentication available to Web applications. It was first defined in the HTTP specification itself and it is by no means elegant, but it gets the job done.

* How it works?

    - First client makes a request to server for a protected resource without any credentials

        GET /test/secure HTTP/1.0

    - Then The server will reply with an access denied message containing a WWW-Authenticate header requesting Basic authentication credentials.

    NOTE - This reponse comes as a seperate operating system prompt, included in this prompt is a request for "realm" (most implementations typically set the realm to the hostname or IP address of the Web server by default).

        HTTP/1.1 401 Unauthorized
        WWW-Authenticate: Basic realm="luxor"

    - Once the user types in his or her password, the browser reissues the requests, this time with the authentication credentials

        GET /test/secure HTTP/1.0
        Authorization: Basic dGVzdDp0ZXN0

    Note that the client has essentially just re-sent the same request, this time with an Authorization header. The server then responds with either another “unauthorized” message if the credentials are incorrect, a redirect to the resource requested, or the resource itself, depending on the server implementation


* What's the problem?

- Basic authentication is wide open to eavesdropping attacks, it sends value in the Authorization header.

- One is that most browsers, including Internet Explorer and Netscape, will cache Basic authentication credentials and send them automatically to all pages in the realm, whether it uses SSL or not.

* The use of 128-bit SSL encryption can thwart these attacks, and is strongly recommended for all Web sites that use Basic authentication.

# Digest Authentication

* Digest authentication was designed to provide a higher level of security than Basic authentication.
* Digest auth is based on a challenge-response authentication model. 

* How it works?

- The users makes a request without authentication credentials.

- In Response the server challenges the client with a random value called a "nonce" and with a WWW-Authenticate header indicating credentials are required to access the requested resource

- The browser then uses a one-way cryptographic function to create a message digest of the username, the password, the given nonce value, the HTTP method, and the requested URI


* How its better?

- Base64 encoding it of no use as anyone can intercept and decode it. which is evesdopping, but using "nonce" and  using MD5 Hashing algorithm/ message digest function makes it difficult for anyone to attack against database.

- here "nonce" is similar to using salt in password schemes

- Digest authentication is a significant improvement over Basic authentication, primarily because the user’s cleartext password is not passed over the wire. This makes it much more resistant to eavesdropping attacks than Basic auth.


* What's the problem?

While Digest solves the problem of authenticating the client over an insecure channel it makes it necessary to store the passwords at the server in plain or in some equivalent form in order to verify the data sent by the client. This shifts the vulnerability problem from the data transport to the server. And in effect it enables an attacker to not compromise a single account but zillions at once.

Which means you should better use TLS to secure the channel and keep the password stored in a secure in irreversible form, so that an attacker cannot compromise accounts easily and en mass. Additionally this solves the problem of missing identification of the server.