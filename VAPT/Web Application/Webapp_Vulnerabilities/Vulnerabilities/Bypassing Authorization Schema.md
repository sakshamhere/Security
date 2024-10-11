https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema

# Testing for Horizontal Bypassing Authorization Schema

For every function, specific role, or request that the application executes, it is necessary to verify:

    Is it possible to access resources that should be accessible to a user that holds a different identity with the same role or privilege?
    Is it possible to operate functions on resources that should be accessible to a user that holds a different identity?

For each role:

    Register or generate two users with identical privileges.
    Establish and keep two different sessions active (one for each user).
    For every request, change the relevant parameters and the session identifier from token one to token two and diagnose the responses for each token.
    An application will be considered vulnerable if the responses are the same, contain same private data or indicate successful operation on other users’ resource or data.

`Example`, suppose that the viewSettings function is part of every account menu of the application with the same role, and it is possible to access it by requesting the following URL: https://www.example.com/account/viewSettings. Then, the following HTTP request is generated when calling the viewSettings function:

    POST /account/viewSettings HTTP/1.1
    Host: www.example.com
    [other HTTP headers]
    Cookie: SessionID=USER_SESSION

    username=example_user

Valid and legitimate response:

    HTTP1.1 200 OK
    [other HTTP headers]

    {
    "username": "example_user",
    "email": "example@email.com",
    "address": "Example Address"
    }

Now The attacker may try and execute that request with the same username parameter:

    POST /account/viewCCpincode HTTP/1.1
    Host: www.example.com
    [other HTTP headers]
    Cookie: SessionID=ATTACKER_SESSION

    username=example_user

If the attacker’s response contain the data of the example_user, then the application is vulnerable for lateral movement attacks, where a user can read or write other user’s data.

# Testing for Vertical Bypassing Authorization Schema

A vertical authorization bypass is specific to the case that an attacker obtains a role higher than their own