# Authorization Testing
- Privilage Esclation
- IDOR

# Session Management Testing

All interaction between the client and application should be tested at least against the following criteria:

- Are all Set-Cookie directives tagged as Secure?
- Do any Cookie operations take place over unencrypted transport?
- Can the Cookie be forced over unencrypted transport?
- If so, how does the application maintain security?
- Are any Cookies persistent?
- What Expires times are used on persistent cookies, and are they reasonable?
- Are cookies that are expected to be transient configured as such?
- What HTTP/1.1 Cache-Control settings are used to protect Cookies?
- What HTTP/1.0 Cache-Control settings are used to protect Cookies?

# Testing for Cookie attribute

Ensure that the proper security configuration is set for cookies.

- Secure attribute
- HttpOnly attribute
- Domain attribute


