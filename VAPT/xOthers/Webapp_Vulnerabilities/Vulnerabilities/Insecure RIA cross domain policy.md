# Insecure RIA cross domain policy
https://beaglesecurity.com/blog/support/vulnerability/2018/06/29/Insecure-RIA-cross-domain-policy.html
https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/08-Test_RIA_Cross_Domain_Policy


Rich Internet Applications use Adobe’s crossdomain.xml policy files to allow cross-domain access to data. These policy files serve the usage via Oracle Java, Adobe Flash and so on. For using these policy files, the domain must grant remote access to other domains. 

These policy files can describe access restrictions if these restrictions are poorly configured, the server will be vulnerable to attacks like Cross-site request forgery attacks and might allow 3rd party domains to access sensitive information.

Example

The following code is the example of a vulnerable cross-domain policy.

      <cross-domain-policy>
         <site-control permitted-cross-domain-policies="all"/>
         <allow-access-from domain="*" secure="false"/>
         <allow-http-request-headers-from domain="*" headers="*" secure="false"/>
      </cross-domain-policy>

   