# What is it

- API penetration testing is an ethical hacking process to assess the security of the API design.

- API pentests are performed on a wide variety of protocols and schemes including REST, SOAP, and RPC.

# Why

- API testing validates the security of your methods and corresponding data.

- Because API is included in almost all web applications and mobile applications, it is critical that API penetration testing be included in your security testing plan.

- APIs often come with well-documented information about their implementation and internal structure - making them ideal targets for a would-be attacker. 

# What is done

- Authentication, encryption, and business logic should all be tested.

- security experts should fully review any documentation and examine all the requests, headers, and parameters.

- It is designed to determine if an API is susceptible to vulnerabilities that may include the following:

    - Sensitive information disclosure.
    - API Mass Assignment.
    - Bypass of access controls.
    - Broken authentication.
    - SQL Injection and other input validation flaws.

- An API pentest should ask questions such as:

    - Should password hashes be disclosed to users?
    - Should users see the locations of other users?

- It’s an easy pitfall for developers to encounter where API responses return the entire state of an object rather than the minimum amount of information necessary for users to have.

- API Mass Assignment  - It is a condition where a client can overwrite server-side variables that the application should not allow. This is often a high risk vulnerability that can allow users to escalate privileges and manipulate business logic.

- API authentication schemes have unique security requirements as well. A holistic API pentest should review how access tokens are generated and revoked, and dive into specific weaknesses of those tokens.

- CSRF,XSS,CORS etc

# Tools used

Frameworks like Burpsuite are commonly used to tamper with parameters and scan requests.

But the most meaningful API testing is done when integrating Postman or Swagger UI with these testing frameworks.


# Test apis
https://github.com/erev0s/VAmPI
https://github.com/roottusk/vapi
https://github.com/InsiderPhD/Generic-University


# cheatsheet
REST testing - https://github.com/OWASP/CheatSheetSeries/blob/3a8134d792528a775142471b1cb14433b4fda3fb/cheatsheets/REST_Assessment_Cheat_Sheet.md
               https://github.com/OWASP/CheatSheetSeries/blob/3a8134d792528a775142471b1cb14433b4fda3fb/cheatsheets/REST_Security_Cheat_Sheet.md
               
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/web-api-pentesting#api-security-empire-cheat-sheet