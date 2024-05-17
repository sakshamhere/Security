# Server Side Template Injection (SSTI)

https://github.com/epinna/tplmap

Tplmap assists the exploitation of Code Injection and Server-Side Template Injection vulnerabilities with a number of sandbox escape techniques to get access to the underlying operating system.

The tool and its test suite are developed to research the SSTI vulnerability class and to be used as offensive security tool during web application penetration tests.

The sandbox break-out techniques came from James Kett's Server-Side Template Injection: RCE For The Modern Web App, other public researches [1] [2], and original contributions to this tool [3] [4].

It can exploit several code context and blind injection scenarios. It also supports eval()-like code injections in Python, Ruby, PHP, Java and generic unsandboxed template engines.

Tplmap is able to detect and exploit SSTI in a range of template engines to get access to the underlying file system and operating system. Run it against the URL to test if the parameters are vulnerable.


# example

HTB lab - Templated

