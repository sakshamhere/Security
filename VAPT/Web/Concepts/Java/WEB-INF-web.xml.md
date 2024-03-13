https://cloud.google.com/appengine/docs/legacy/standard/java/config/webxml
https://securityboulevard.com/2020/05/seven-security-misconfigurations-in-java-web-xml-files/

# web.xml deployment descriptor

Java web applications use a deployment descriptor file to determine how URLs map to servlets, which URLs require authentication, and other information. 

This file is named web.xml, and resides in the app's WAR under the WEB-INF/ directory. web.xml is part of the servlet standard for web applications.

web.xml defines mappings between URL paths and the servlets that handle requests with those paths.

The web server uses this configuration to identify the servlet to handle a given request and call the class method that corresponds to the request method.

The WEB-INF/web.xml Deployment Descriptor file describes how to deploy a web application in a servlet container such as Tomcat. Normally, this file should not be accessible. 



* risks
information disclosure
file path traversal / manipulation
directory traversal