# What is Cookie

HTTP Cookie is small piece of data that server send's user browser, the browser stores it and send it to server for later request.

Cookie is made to remember the stateful information for stateless HTTP protocol

# Purpose of Cookie

- Session Management    - logins, shopping cart, score etc which server should remember while user is logged in.

- Tracking              - Recording and analyzing user behavior

# Cookie lifetime

Cookie lifetime is defined by any of the two atttribute



# Cookie 

-  Domain       - The Domain attribute specifies which hosts can receive a cookie. 
                  If the server does not specify a Domain, the browser defaults the domain to the same host that set the cookie, excluding subdomains. 

                  If Domain is specified, then subdomains are always included. Therefore, specifying Domain is less restrictive than omitting it.

                  However, it can be helpful when subdomains need to share information about a user.

                  For example, if you set Domain=mozilla.org, cookies are available on subdomains like developer.mozilla.org.

-  Path         - The Path attribute indicates a URL path that must exist in the requested URL in order to send the Cookie 
                  header. 

                  For example, if you set Path=/docs, these request paths match:

                    /docs, /docs/, /docs/Web/, /docs/Web/HTTP
                    
                    But these request paths don't:
                    /, /docsets, /fr/docs