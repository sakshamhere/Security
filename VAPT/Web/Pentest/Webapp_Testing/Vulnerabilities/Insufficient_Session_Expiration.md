
Insufficient Session Expiration is when a web site permits the attacker to reuse old session credentials or session IDs for authorization, Since HTTP is a stateless protocol, websites commonly use cookies to store session IDs that uniquely identify a user from request to request. Consequently each sessions IDs confidentially must be maintained to prevent multiple users from accessing the same account. A stolen session ID can be used to view users account or perform a Fraudulent transaction.

Steps

1. Browse the app

2. Logout the app

3. Take any previous recorded request and send it to the repeater

4. issue the request to server and you will find that application session cookie was not

5. Only after 10-15 min period does the cookie expires if no request are submitted and cookie isnt refreshed,  Otherwise the application will continiously referesh the cookie with each new request.

