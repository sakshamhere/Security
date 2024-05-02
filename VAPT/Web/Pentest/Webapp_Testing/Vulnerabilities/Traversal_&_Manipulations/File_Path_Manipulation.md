https://portswigger.net/kb/issues/00100b00_file-path-manipulation

File path manipulation vulnerabilities arise when user-controllable data is placed into a file or URL path that is used on the server to access local resources, which may be within or outside the web root. 

If vulnerable, an attacker can modify the file path to access different resources, which may contain sensitive information. 

Even where an attack is constrained within the web root, it is often possible to retrieve items that are normally protected from direct access, such as application configuration files, the source code for server-executable scripts, or files with extensions that the web server is not configured to serve directly.

for example - web.xml / deployment discriptor

poc
https://demo.testfire.net/index.jsp?content=business.htm

https://demo.testfire.net/index.jsp?content=../WEB-INF/web.xml