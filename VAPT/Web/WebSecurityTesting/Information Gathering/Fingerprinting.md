1. Fingerprinting Webserver
2. Fingerprint the components being used by the web applications.
3. Identify possible entry and injection points through request and response analysis.
4. Test HTTP Methods
    - Discover the Supported Methods   
    - Testing for (XST) attak / Cross-Site Tracing Potential 
    - Testing for HTTP Method Overriding

5. Test HTTP Strict Transport Security header
6. Testing for RIA Cross Domain Policy Files Weakness
7. Testing for Encryption
    - Assess use of HTTP instead of HTTPS

# Fingerprinting Webserver

1. Banner Grabbing

A banner grab is performed by sending an HTTP request to the web server and examining its response header.
This can be accomplished using a variety of tools, including telnet for HTTP requests, or openssl for requests over SSL.

For example, here is the response to a request from an Apache server.

HTTP/1.1 200 OK
Date: Thu, 05 Sep 2019 17:42:39 GMT
Server: Apache/2.4.41 (Unix)
....

* The server type and version is clearly exposed. However, security-conscious applications may obfuscate their server information by modifying the header. For example, here is an excerpt from the response to a request for a site with a modified header:

HTTP/1.1 200 OK
Server: Website.com
Date: Thu, 05 Sep 2019 17:57:06 GMT
Content-Type: text/html; charset=utf-8
Status: 200 OK
...

In cases where the server information is obscured, testers may guess the type of server based on the ordering of the header fields

2. Sending Malformed Requests to get default error pages

Web servers may be identified by examining their error responses, and in the cases where they have not been customized, their default error pages.
One way to compel a server to present these is by sending intentionally incorrect or malformed requests.

As default error pages offer many differentiating factors between types of web servers, their examination can be an effective method for fingerprinting even when server header fields are obscured

3. Using Automated tool

Here are some commonly-used scan tools that include web server fingerprinting functionality.

Netcraft, an online tool that scans websites for information, including the web server.
Nikto, an Open Source command-line scanning tool.
Nmap, an Open Source command-line tool that also has a GUI, Zenmap.

* Remediation
While exposed server information is not necessarily in itself a vulnerability, it is information that can assist attackers in exploiting other vulnerabilities that may exist.
For this reason it is recommended that some precautions be taken. These actions include:

- Obscuring web server information in headers, such as with Apache’s mod_headers module.
- Using a hardened reverse proxy server to create an additional layer of security between the web server and the Internet.
- Ensuring that web servers are kept up-to-date with the latest software and security patches.

# Identify possible entry and injection points through request and response analysis.

Before any testing begins, the tester should always get a good understanding of the application and how the user and browser communicates with it.

They should pay special attention to when GET requests are used and when POST requests are used to pass parameters to the application. In addition, they also need to pay attention to when other methods for RESTful services are used.

- Identify where GETs are used and where POSTs are used.
- Identify all parameters used in a POST request (these are in the body of the request).
- Identify all parameters used in a GET request (i.e., URL), in particular the query string (usually after a ? mark).
- Identify where there are any redirects (3xx HTTP status code), 400 status codes, in particular 403 Forbidden, and 500 internal server errors during normal responses (i.e., unmodified requests).
- Identify where new cookies are set (Set-Cookie header), modified, or added to.
- Also note where any interesting headers are used. For example, Server: BIG-IP indicates that the site is load balanced. Thus, if a site is load balanced and one server is incorrectly configured, then the tester might have to make multiple requests to access the vulnerable server, depending on the type of load balancing used.

# Fingerprint the components being used by the web applications.

There are several common locations to consider in order to identify frameworks or components:

- HTTP headers
- Cookies
- HTML source code
- Specific files and folders
- File extensions
- Error messages

# Test HTTP Methods

- Discover the Supported Methods    

While the OPTIONS HTTP method provides a direct way to do that, verify the server’s response by issuing requests using different methods. This can be achieved by manual testing or something like the http-methods Nmap script.

To use the http-methods Nmap script to test the endpoint /index.php on the server localhost using HTTPS, issue the command:

nmap -p 443 --script http-methods --script-args http-methods.url-path='/index.php' localhost

- Testing for (XST) attak / Cross-Site Tracing Potential

The TRACE method, intended for testing and debugging, instructs the web server to reflect the received message back to the client. This method, while apparently harmless, can be successfully leveraged in some scenarios to steal legitimate users’ credentials. This attack technique was discovered by Jeremiah Grossman in 2003, in an attempt to bypass the HttpOnly attribute that aims to protect cookies from being accessed by JavaScript. However, the TRACE method can be used to bypass this protection and access the cookie even when this attribute is set.

- Testing for HTTP Method Overriding

he main purpose of this is to circumvent some middleware (e.g. proxy, firewall) limitation where methods allowed usually do not encompass verbs such as PUT or DELETE. The following alternative headers could be used to do such verb tunneling:

X-HTTP-Method
X-HTTP-Method-Override
X-Method-Override

The web server in the following example does not allow the DELETE method and blocks it:

$ ncat www.example.com 80
DELETE /resource.html HTTP/1.1
Host: www.example.com

HTTP/1.1 405 Method Not Allowed

After adding the X-HTTP-Header, the server responds to the request with a 200:

$ ncat www.example.com 80
DELETE /resource.html HTTP/1.1
Host: www.example.com
X-HTTP-Method: DELETE

HTTP/1.1 200 OK
Date: Sat, 04 Apr 2020 19:26:01 GMT
Server: Apache

# Test for HSTS

The HTTP Strict Transport Security (HSTS) feature lets a web application inform the browser through the use of a special response header that it should never establish a connection to the specified domain servers using un-encrypted HTTP. Instead, it should automatically establish all connection requests to access the site through HTTPS. It also prevents users from overriding certificate errors.

Review the HSTS header and its validity.

# Testing for RIA Policy Files Weakness

Rich Internet Applications (RIA) have adopted Adobe’s crossdomain.xml policy files to allow for controlled cross domain access to data and service consumption using technologies such as Oracle Java, Silverlight, and Adobe Flash. Therefore, a domain can grant remote access to its services from a different domain.

Whenever a web client detects that a resource has to be requested from other domain, it will first look for a policy file in the target domain to determine if performing cross-domain requests, including headers, and socket-based connections are allowed.

Master policy files are located at the domain’s root. A client may be instructed to load a different policy file but it will always check the master policy file first to ensure that the master policy file permits the requested policy file

However, often the policy files that describe the access restrictions are poorly configured. Poor configuration of the policy files enables Cross-site Request Forgery attacks, and may allow third parties to access sensitive data meant for the user.

Review and validate the policy files.

For example, if the application’s URL is http://www.owasp.org, the tester should try to download the files http://www.owasp.org/crossdomain.xml and http://www.owasp.org/clientaccesspolicy.xml.

After retrieving all the policy files, the permissions allowed should be be checked under the least privilege principle. Requests should only come from the domains, ports, or protocols that are necessary. Overly permissive policies should be avoided. Policies with * in them should be closely examined.

# Testing for Encryption

Assess whether any use case of the web site or application causes the server or the client to exchange credentials without encryption.

Set up and start a tool to capture traffic
In the captured traffic, look for sensitive data including the following:

Passphrases or passwords, usually inside a message body
Tokens, usually inside cookies
Account or password reset codes