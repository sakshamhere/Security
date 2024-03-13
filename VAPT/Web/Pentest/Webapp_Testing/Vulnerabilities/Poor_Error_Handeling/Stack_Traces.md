https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces


Stack traces are not vulnerabilities by themselves, but they often reveal information that is interesting to an attacker. Attackers attempt to generate these stack traces by tampering with the input to the web application with malformed HTTP requests and other input data.

If the application responds with stack traces that are not managed it could reveal information useful to attackers. This information could then be used in further attacks. Providing debugging information as a result of operations that generate errors is considered a bad practice due to multiple reasons. For example, it may contain information on internal workings of the application such as relative paths of the point where the application is installed or how objects are referenced internally.


Some tests to try include:

    invalid input (such as input that is not consistent with application logic).
    input that contains non alphanumeric characters or query syntax.
    empty inputs.
    inputs that are too long.
    access to internal pages without authentication.
    bypassing application flow.

All the above tests could lead to application errors that may contain stack traces. It is recommended to use a fuzzer in addition to any manual testing.

Some tools, such as OWASP ZAP and Burp proxy will automatically detect these exceptions in the response stream as you are doing other penetration and testing work.