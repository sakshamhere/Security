refer - 
- https://securecode.wiki/docs/lang/python/#a7--cross-site-scripting-xss
- https://security.openstack.org/guidelines/dg_cross-site-scripting-xss.html
- https://semgrep.dev/docs/cheat-sheets/flask-xss/
- https://flask.palletsprojects.com/en/1.1.x/security/

# XSS
1. Validate user input based on a whitelist
2. Sanitize user provided data from any character that can be for malicious purpose
3. Escape the following characters with HTML entity encoding to prevent switching into any execution context, such as script, style, or event handlers

    & --> &amp;
    < --> &lt;
    > --> &gt;
    " --> &quot;
    ' --> &#x27;
    / --> &#x2F;

4. Output Encoding - Encode user-provided data being reflected as output. Adjust the encoding to the output context so that, 
                    for example, HTML encoding is used for HTML content, HTML attribute encoding is used for attribute values, and JavaScript encoding is used for server-generated JavaScript.
5. Implement Content Security Policy

Note - When sanitizing or encoding data, it is recommended to only use libraries specifically designed for security purposes. 
       Also, make sure that the library you are using is being actively maintained and is kept up-to-date with the latest discovered vulnerabilities


       &quot;&gt;&lt;img src=1 onerror=alert(1)&gt;