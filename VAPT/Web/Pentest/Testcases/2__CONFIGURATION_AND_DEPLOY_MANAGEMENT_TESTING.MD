# 1. TEST FILE EXTENSION HANDELLING FOR SENSITIVE INFORMATION

- Find important file, information (.asa, .inc, .sql, .tar, .pdf, txt etc)

# 2. BACKUP AND UNREFERENCED FILE FOR SENSETIVE INFORMATION

- Check JS source code, comments, cache files, backup file (.old, .bak, .inc, .src) and guessing of filename

# 3. Enumerate Infrastructure and Application Admin Interface

- Directory and file enumeration, comments and links in source (/admin, /administrator, /backoofice, /backend etc), alternative server port (tomcat/8080)

# 4. Test HTTP Methods

- Identify HTTP allowed methods on Web server with OPTIONS, Arbitrary HTTP methods, HEAD access control bypass and XST

# 5. Test RIA cross domain policy

- Analyse the permissions allowed from the policy files (crossdomain.xml/clientaccesspolicy.xml)


Tools used
# Nikto, Browser
# Nessus, Nikto, Wikto
# Burp proxy, dirb, Dirbustur, fuzzdb, Tide Scanner
# netcat, curl
# Burp proxy, ZAP, Nikto

**********************************************************************************************************************************************

# 4. Test HTTP Methods

Test Objectives

    Enumerate supported HTTP methods.
    Test for access control bypass.
    Test XST vulnerabilities.
    Test HTTP method overriding techniques.


valid HTTP request methods, or verbs:

    GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE

However, most web applications only need to respond to GET and POST requests, Since the other methods are so rarely used, many developers do not know, or fail to take into consideration, how the web server or application framework’s implementation of these methods impact the security features of the application.


1. Discover the Supported Methods

- nmap -p 80 --script http-methods  192.168.46.129    

- curl -X OPTIONS <target>


# 5. Test RIA Cross Domain Policy

Rich Internet Applications (RIA) have adopted Adobe’s crossdomain.xml policy files to allow for controlled cross domain access to data and service consumption using technologies such as Oracle Java, Silverlight, and Adobe Flash. Therefore, a domain can grant remote access to its services from a different domain. However, often the policy files that describe the access restrictions are poorly configured. Poor configuration of the policy files enables Cross-site Request Forgery attacks, and may allow third parties to access sensitive data meant for the user.