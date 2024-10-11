# Missing and Misconfiguration checks
- X-Frame-options
- Cache-control
- Secure, HttpOnly, Samesite, Domain, Path, Expires(for persistent cookie)
- HSTS
- X-Powered-by
- Host override headers - Forwarded, X-Forwarded-For, X-Forwarded-Host,X-Forwarded-Proto
- Server
- HTTP Methods allowed
- Post as Get
- Host Header injection
- CORS
- Weak Cipher Suite

# Authentication checks
- Basic Auth
- Autocomplete feature
- Credentials transported over HTTP
- bypass by parameter modification
- 

# Access control/Authorization checks
- Forced Browsing
- IDOR
- Biusness Logic
- Horizontal Bypassing Authorization Schema ()
- Privilage Esclation
- Directory Traversal
- JWT checks

# Session related checks
- Session Management - reasonable expiration, secure, randomness/presiction
- Cookie attributes - Secure, HttpOnly, Samesite, Domain, Path, Expires(for persistent cookie)
- Logout functionality
- session invalidation / session timeout (if expired token can be reused)
- session fixation (session id regeneration)
- Session Hijacking (secure attribute)
- sensetive data visible after session timeout
- concurrent sessions

# Information Leakage checks
- poor error handeling, stack traces
- sensitive data in query parameter

# CRSF checks
- Token validation if present
- POC execution
- XMLHttp POC (Modern browsers use CORS in APIs such as XMLHttpRequest or Fetch to mitigate the risks of cross-origin HTTP requests.)

# Injection checks
- SQL  
- XSS
- Command
- CSV / Formula
- HTML
- CSS
- HTTP Parameter Pollution
- Host Header
- Improper data validation
- LDAP injection
- XML injection
- Xpath injection
- Client side Json injection
- JSON Hijacking

# Other Client Side issues

- URL Redirect
- CORS
- Cross Site Flashing
- Testing Websockets
- Testing Web Messaging
- Testing Local Storage

# File Inclusion checks
- Remote File Inclusion
- Local File Inclusion

# File upload checks
- extenstion validation
- bypassing checks

# HTTP Request Smuggeling

# SSRF check

# Server Side Template Injection