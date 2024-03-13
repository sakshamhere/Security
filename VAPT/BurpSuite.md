# Burp Scanner
# Burp Proxy
# Burp Intruder
# Burp Repeater
# Target
# Sequencer
# Decoder
# Comparer


# Burp Scanner
Key phases

1. Crawling for content - https://portswigger.net/burp/documentation/scanner/crawling

- navigating around the application
- following links
- submitting forms
- logging in where necessary to catalog the content of the application and the navigational paths within it.

2. Auditing for Vulnerabilities in content - https://portswigger.net/burp/documentation/scanner/auditing

This involves analyzing the application's traffic and behavior to identify security vulnerabilities and other issues. Depending on the scan configuration, it may involve sending a large/small number of requests to the application

* Audit Phases

- Passive phases
- Active phases
- JavaScript analysis phases

* Issue and Issue types

Burp is able to detect a huge variety of issues, including security vulnerabilities and other items of informational interest.

Issue Types:

1. Passive - These are issues that can be detected purely by inspecting the application's normal requests and responses

For Example - 

> Serialized object in HTTP message - Applications may submit a serialized object in a request parameter. This behavior can expose the application in various ways, including:

Any sensitive data contained within the object can be viewed by the user.
An attacker may be able to interfere with server-side logic by tampering with the contents of the object and re-serializing it.

Related Vulnerability

> Insecure Deserialization - https://portswigger.net/web-security/deserialization

Insecure deserialization is when user-controllable data is deserialized by a website. This potentially enables an attacker to manipulate serialized objects in order to pass harmful data into the application code.

2. Light active - These are issues that can be detected by making a small number of benign additional requests.