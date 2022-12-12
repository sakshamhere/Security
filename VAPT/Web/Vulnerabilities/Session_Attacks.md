# Session Fixation
https://owasp.org/www-community/attacks/Session_fixation

The attack explores a limitation in the way the web application manages the session ID, more specifically the vulnerable web application. 

When authenticating a user, it doesn’t assign a new session ID, making it possible to use an existent session ID. The attack consists of obtaining a valid session ID (e.g. by connecting to the application), inducing a user to authenticate himself with that session ID, and then hijacking the user-validated session by the knowledge of the used session ID. 

The attacker has to provide a legitimate Web application session ID and try to make the victim’s browser use it.

NOTE - The session fixation attack is not a class of Session Hijacking, which steals the established session between the client and the Web Server after the user logs in. Instead, the Session Fixation attack fixes an established session on the victim’s browser, so the attack starts before the user logs in.

Below are some of the most common techniques to fix session:

- Session token in the URL argument
- Session token in a hidden form field
- Session ID in a cookie
    - Client-side script (XSS)


• Session token in the URL argument: The Session ID is sent to the victim in a hyperlink and the victim accesses the site through the malicious URL.

• Session token in a hidden form field: In this method, the victim must be tricked to authenticate in the target Web Server, using a login form developed for the attacker. The form could be hosted in the evil web server or directly in html formatted e-mail.

• Session ID in a cookie:

    o Client-side script

    Most browsers support the execution of client-side scripting. In this case, the aggressor could use attacks of code injection as the XSS (Cross-site scripting) attack to insert a malicious code in the hyperlink sent to the victim and fix a Session ID in its cookie.


# Session Hijacking
https://owasp.org/www-community/attacks/Session_hijacking_attack

The Session Hijacking attack consists of the exploitation of the web session control mechanism, which is normally managed for a session token.

he Session Hijacking attack compromises the session token by stealing or predicting a valid session token (for ex session Id) to gain unauthorized access to the Web Server.

The session token like sesionn ID could be compromised in different ways; the most common are:

- Predictable session token;
- Session Sniffing;
- Client-side attacks (XSS, malicious JavaScript Codes, Trojans, etc);
- Man-in-the-middle attack
- Man-in-the-browser attack