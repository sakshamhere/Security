
# 1. Testing for Bypassing Session Management Schema

- SessionID anaylysis prediction

- unencrypted cookie transport

- brute-force

# 2. Testing for cookie atttributes

- check for HTTPOnly and Secure flag

- check for cookie expiration

- check for sensitive data

# 3. Testing for Session Fixation

- The application dosent renew cookie after a successful user authentication

# 4. Testing for Exposed Session Variables

- Test for encryption and reuse of session token vulnerabilities

# 5. Testing for Cross Site Request Forgery

- URL analysis,  detect functions without token

# 6. Testing for logout functionality

- check reuse sessoin after logout bother server side and SSO (DTCC- does not requie redirection to login page simply try to resubmit a previous request usnig burp)

# 7. Test for Session Timeout

- Check session timeout after the timeout has passed, all session tokens should be destroyed or be unusable

# 8. Test for Session Puzzling

- The application uses the same session variables for more than one purpose, An attacker can potentialy access pages in an order unanticipated by the developer so that the session variable is set in one context and then used in another

