https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

# Session 

HTTP is a stateless protocol (RFC2616 section 5), where each request and response pair is independent of other web interactions.

Modern and complex web applications require the retaining of information or status about each user for the duration of multiple requests. 

Web applications can create sessions to keep track of anonymous users after the very first user request. An example would be maintaining the user language preference.

# Session ID

In order to keep the authenticated state and track the users progress within the web application, applications provide users with a session identifier (session ID or token) that is assigned at session creation time, and is shared and exchanged by the user and the web application for the duration of the session (it is sent on every HTTP request). The session ID is a name=value pair

Once an authenticated session has been established, the session ID (or token) is temporarily equivalent to the strongest authentication method used by the application, such as username and password, passphrases, one-time passwords (OTP), client-based digital certificates, smartcards, or biometrics (such as fingerprint or eye retina)

The session ID or token binds the user authentication credentials (in the form of a user session) to the user HTTP traffic and the appropriate access controls enforced by the web application. 

- The name used by the session ID should not be extremely descriptive nor offer unnecessary details 

- The session ID must be long enough to prevent brute force attacks,The session ID length must be at least 128 bits (16 bytes)

- The session ID must be unpredictable (random enough) to prevent guessing attacks,Additionally, a random session ID is not enough; it must also be unique to avoid duplicated IDs

- The session ID content (or value) must be meaningless to prevent information disclosure attacks,

- It is essential to use an encrypted HTTPS (TLS) connection for the entire web session,Additionaly Secure cookie attribute must be used to ensure the session ID is only exchanged through an encrypted channel.




# The session ID regeneration 
https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-generation-and-verification-permissive-and-strict-session-management