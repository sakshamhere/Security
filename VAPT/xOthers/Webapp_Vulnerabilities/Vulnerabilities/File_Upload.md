https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

File upload vulnerabilities are when a web server allows users to upload files to its filesystem without sufficiently validating things like their name, type, contents, or size.

# Impact 

The impact of file upload vulnerabilities generally depends on two key factors:

1. Which aspect of the file the website fails to validate properly, whether that be its size, type, contents, and so on.
2. What restrictions are imposed on the file once it has been successfully uploaded.

In the worst case scenario, the file's type isn't validated properly, and the server configuration allows certain types of file (such as .php and .jsp) to be executed as code. In this case, an attacker could potentially upload a server-side code file that functions as a web shell, effectively granting them full control over the server.

If the server is also vulnerable to directory traversal, this could mean attackers are even able to upload files to unanticipated locations.

Typical Impact

- Remote Code Execution: 

An attacker can try to e.g. upload a web shell which enables him to pass on terminal commands to the server running the application.

- Denial of Service: 

If the application code is not validating file size or the number of files uploaded, an attacker could try to fill up the server’s storage capacity until a point is reached, where the application cannot be used anymore.

- Web Defacement:

An attacker could substitute existing web pages with his own content 

- Phishing Page:

An attacker could also go ahead only slightly manipulate an existing page in order to e.g. extract sensitive data, sending it to a destination controlled by himself.

File upload vulnerabilities often go hand-in-hand with directory traversal vulnerabilities.

# Threats

Attack can -

- Exploit vulnerabilities in the file parser or processing module
- Use the file for phishing
- Send ZIP bombs, XML bombs or simply huge files in a way to fill the server storage which hinders and damages the server's availability
- Overwrite an existing file on the system

If the file uploaded is publicly retrievable,then Attacker can -

- Client-side active content (XSS, CSRF, etc.) that could endanger other users if the files are publicly retrievable.
- Public disclosure of other files
- Initiate a DoS attack by requesting lots of files. Requests are small, yet responses are much larger
- File content that could be deemed as illegal, offensive, or dangerous (e.g. personal data, copyrighted data, etc.) which will make you a host for such malicious files


* Malicious file


# Prevent

Extension Validation

- Ensure that the validation occurs after decoding the file name
- Ensure proper filter is set in place in order to avoid certain known bypasses such as -
    - Double extensions, e.g. .jpg.php, where it circumvents easily the regex \.jpg
    - Null bytes, e.g. .php%00.jpg, where .jpg gets truncated and .php becomes the new extension
    - Generic bad regex that isn't properly tested and well reviewed.
- Ensure the usage of business-critical extensions only, without allowing any type of non-required extensions.

- Use existing well-tested validation frameworks for file uploads
- Validate the file type, don't trust the Content-Type header as it can be spoofed
- Ensure that input validation is applied before validating the extensions
- Implement allow-list containing only the file types which are really necessary for the proper functioning of the web app
- Restrict file size to a certain limit
- Host uploaded files on a separate domain from the main application, Store the files on a different server.
- Run the file through an antivirus or a sandbox if available to validate that it doesn't contain malicious data
- Protect the file upload from CSRF attacks
- Remove EXIF data from uploaded files