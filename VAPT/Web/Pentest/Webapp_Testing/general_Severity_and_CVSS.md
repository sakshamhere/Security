



#  VULNERABILITY                                            SEVERITY           OWASP_CATAGORY          CWE ID

* CLICKJACKING-X-FRAME-OPTIONS HEADER MISSING                   LOW                                              

* COOKIE SECURITY: COOKIE NOT SENT OVER SSL                     LOW             CRYPTOGRAPHIC FAILURES  

* COOKIE SECURITY: COOKIE IS NOT HTTPONLY                       LOW             SECURITY MISCONFIGURATION

* MISSING HTTP-STRICT TRANSSPORT SECURITY HEADER                LOW             CRYPTOGRAPHIC FAILURES

* HOST HEADER POISONING                                         LOW             INJECTION

* SERVER MISCONFIGURATION - CACHE POLICY                        LOW             SECURITY MISCONFIGURATION

* CACHED SSL CONTENT                                            LOW             SECURITY MISCONFIGURATION

* SERVER BANNER DISCLOSURE                                      LOW             SECURITY MISCONFIGURATION

* PRIVILAGE ESCALATON                                           LOW

* UNWANTED HTTP METHODS SUPPORTED                               LOW             INSECURE DESIGN

* POST PARAMETER ACCEPTED AS GET PARAMETER                      LOW             INSECURE DESIGN

* CERTIFICATE SIGHNED USING WEAK HASH ALGORITHM                 LOW             CRYPTOGRAPHIC FAILURES

* INSUFFICIENT TRANSPORT LAYER PROTECTION WEAK SSL CIPHERS      LOW             CRYPTOGRAPHIC FAILURES

* SESSION NOT INVALIDATED AFTER LOGOUT                          LOW             IDENTIFICATION AND AUTHENTICATION FAILURES

* INCORRECT AUTHORIZATION CHECKS                                LOW             BROKEN ACCESS CONTROL 

* PERMITTING CONCURRENT SESSIONS                                LOW             IDENTIFICATION AND AUTHENTICATION FAILURES

* SECURITY MISCONFIGURATION-COOKIE SCOPED TO PARENT DOMAIN      LOW             SECURITY MISCONFIGURATION

* CONTENT SPOOFING                                              LOW

* HTTP BASIC AUTHENTICATION USED                                LOW             IDENTIFICATION AND AUTHENTICATION FAILURES

* PRIVACY VIOLATION : AUTOCOMPLETE FEATURE                      LOW

* PAGE DO NOT REFRESH AFTER IDLE SESSION TIMEOUT                LOW             IDENTIFICATION AND AUTHENTICATION FAILURES

* POOR ERROR HANDELING: UNHANDELED EXCEPTION                    LOW

* UNWANTED HTTP METHODS ALLOWED                                 LOW

* REVERSE TABNABBING                                            MEDIUM

* POTENTIAL SENSITIVE DATA VISIBLE AFTER IDLE SESSION TIMEOUT   MEDIUM          IDENTIFICATION AND AUTHENTICATION FAILURES

* INFORMATION LEAKAGE                                           MEDIUM

* INFORMATION EXPOSURE THROUGH QUERY STRINGS IN GET REQUEST     MEDIUM          INSECURE DESIGN

* IMPROPER AUTHENTICATION                                       MEDIUM          IDENTIFICATION AND AUTHENTICATION FAILURES

* INSUFFICIENT SESSION EXPIRATION                               MEDIUM          IDENTIFICATION AND AUTHENTICATION FAILURES

* IMPROPER INPUT VALIDATION                                     MEDIUM

* CROSS SITE REQUEST FORGERY                                    MEDIUM          BROKEN ACCESS CONTROL                                         

* BUISSINESS LOGIC ABUSE                                        MEDIUM                                              

* CROSS SITE SCRIPTING - REFLECTED                              MEDIUM          INJECTION

* BLIND SQL INJECTION                                           MEDIUM          INJECTION

* POOR ERROR HANDELING: UNHANDELED EXCEPTION                    MEDIUM

* CSV FORMULA NNJECTIOON                                        MEDIUM          INJECTION

* PARAMETER BASED REDIRECTION                                   MEDIUM

* LACK OF RATE LIMITING - API                                   HIGH

* CROSS SITE SCRIPTING - PERSISTENT                             HIGH            INJECTION

* INSUFFICIENT AUTHORIZATION                                    HIGH            BROKEN ACCESS CONTROL                                   

* IMPROPER ACCESS CONTROL FORCED BROWSING                       HIGH            BROKEN ACCESS CONTROL
   
* INSECURE DIRECT OBJECT REFERENCE                              HIGH            BROKEN ACCESS CONTROL

* MALICIOUS FILE UPLOAD                                         HIGH

* PASSWORD MANAGEMENT-HARDCODED PASSWORD                        HIGH

********************************************************************************************************************************************

# REVERSE TABNABBING 



# POOR ERROR HANDELING: UNHANDELED EXCEPTION

This can be low to high

LOW senerio (ex java exception with 400 bad request)


- Error message that contains `server misconfiguration` and `stack trace errors`, an attacker can find public vulnerabilities listed for this
These message revelas implementation detaisl that should never be revealed to an end user and Provide malicious actors important clues on postential flaws in websites


From a developer perspective, the best method of preventing problems arising from database error messages is to adop secure programming techniques that prevent problems that might arise from an attacker discovering too much information about architecture and design of your web application. The following recommendations can be used as a basis for that.

`Uniform Error Codes` - Ensure that you are not inadvertently supplying information to an attacker via use of inconsistent or conflicting error messages. For example dont reveal unintended information by utilizing error messages such as Access Denied, which will also let an attacker know that the file he seeks actually exist and which have read access denied.

`Informational Error Messages` - Ensure that error messages do not reaveal too much information. Complete or partial paths, variable and file names, row and column names in tables and specific database errors should never be revealed. Remember that an attacker will gather as much as infomration availible to craft attack.

`Proper Error Handling` - Utilize generic pages and error handeling logic to inform end users of potential problems.
********************************************************************************************************************************************

# PASSWORD MANAGEMENT-HARDCODED PASSWORD

It was detected that the CBI Web application is vulnerable to usage of hard-coded password. Tha application stores the databased passwords in "sqlMapConfig.sybase.ds.xml" file in plain text.

Use encoding/encryption in the enviornment files while using the password for making connections to resources from the code, decode/decrypt the password before usage

********************************************************************************************************************************************

# LACK OF RATE LIMITING - API

********************************************************************************************************************************************

# SERVER MISCONFIGURATION - CACHE POLICY                        

Revalidate attribute is missing in cache control

* Remediation

HTTP cache related headers ensure that pages containing sensetive info are not cached by intermediatory proxy servers and local browsers.
proxy servers could redisplay users data to another user, while local browser can expose data by "back" button functionality.

Following Header values must be used to prevent page caching:

- cache-control header (HTTP 1.1) set to "no-store", "no-cache" and "must-revalidate"

- pragma header (HTTP 1.0) set to "no-cache"

- Expires header serverd pre-expired (ie Backdated)

Both (pragma and cache-control) should be used to ensure backwards compatiblity with devices that are not HTTP /1.1 complaint.

# CACHED SSL CONTENT                                            

cache control header is missing

Application uses a cache to maintain a pool of objects, threads, connections, pages, or passwords to minimize the time it takes to access them, if Implemented improperly, these caches can allow access to unauthorized information or cause a denial of serverice vul.

********************************************************************************************************************************************

# CROSS SITE REQUEST FORGERY

Remediation

- Assign a diffent token to every session or implement request per token for more security.

- Validate domain and referer in code for request.

*********************************************************************************************************************************************************

# PARAMETER BASED REDIRECTION                             

It has been found the app is vulnerable to url redirection, on modifying parameter value in url the web app redirects to specified url (google.com in this case)


* Remeditation

- Do not grant visitors control over destination URL, this can be done by using internal links such as "/redirect/123" where 123 corrospond to a valid external url stored in database

- you can allow external redirects to certain websites only.

- Use proxy pages when redirecting users to external websites, this will warn users that they are leaving the trusted website.

- Disabble redirects to external websites on server side

*****************************************************************************************************************************************************

# CERTIFICATE SIGHNED USING WEAK HASH ALGORITHM  

- login to application, verify the certification information

* Remediation

Do not use SHA-1 algorithm as it is now considered cryptographically unsound. Generate a new certificate that is signed with a stronger algorithm such as SHA-2


# INSUFFICIENT TRANSPORT LAYER PROTECTION WEAK SSL CIPHERS

senerio1
- During authentication application may use SSL/TLS but they often fail to make use of it elsewhere in the application leaving data and session IDs exposed which can be intercepted and exploit is done

the web server is supporting TLS1.0/SSLV3.0 which is vulnerable to the Beast, Freak and PODDLE attacks, THIS allows MITM attacks

* Remediation - 

- To Protect server against PDDLE and BEAST, configure it to support only TLS 1.2 and no older protocols, all older SSL and TLS version are now officialy deprecated and all modern browsers such as Chrome, Firefox, support TLS 1.2.
Apply the patches provided by vendor 


semerio2

- The application server has been configured to support weak SSL protocol. it was observed that the server supports TLSv1 protocol
- The server supports following encryption ciphers:
    - TLS_RSA_WITH_3DES_EDE_CBC_SHA
    - TLS_RSA_WITH_RC4_128_MD5
    - TLS_RSA_WITH_RC4_128_SHA

* Remediation

- The application server's configuration should allow connection which implement TLS v1.2 with a cipher key that is atleast 256 bits in length. SSLv3 and TLS v1.1 offer only a moderate level of protection

********************************************************************************************************************************************************

# SERVER BANNER DISCLOSURE   

`Server`

The Server header describes the software used by the origin server that handled the request — that is, the server that generated the response.

This is not a security header, but how it is used is relevant for security.
Recommendation¶

Remove this header or set non-informative values.

    Server: webserver

    NOTE: Remember that attackers have other means of fingerprinting the server technology.

`X-Powered-By`

The X-Powered-By header describes the technologies used by the webserver. This information exposes the server to attackers. Using the information in this header, attackers can find vulnerabilities easier.
Recommendation¶

Remove all X-Powered-By headers.

    NOTE: Remember that attackers have other means of fingerprinting your tech stack.


*********************************************************************************************************************************************************
# SESSION NOT INVALIDATED AFTER LOGOUT                     

- The logout simply tries to close browser tab alone, however if any other open tab is accessed we are able to access application
- After clicking back button app is accessible

* Remediation

- On Logout user sessions should be invalidated and all relevant session identifiers, auth tokens, and application state information should be deleted or overwritten

- Also instead of writing a javascript code to exit browser upon clicking 'Logout' button to terminate session, developer should redirect the page to logput page

- In order to kill the current session, you basically need to call HttpSession#invalidate() and perform redirect to login/main page. this code is supposed to be placed in doPost() method of a servlet which is invoked by a POST request.

Sample Code

@WebServlet("/logout")
Public class LogoutServlet extends HttpServlet{

    @Override
    Protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException{
        request.getSession().invalidate();
        response.sendRedirect(request.getContextPath() + "/Loginpage.html")'
    }
}

This piece of code shouldnt be used over every single page, you should be performing this job in a single place in servlet filter.

- Further there's another potential problem when end user uses the browsers back button to navigate back in history. By default, the browser will cache all responses and thus back button might display the page from browsers cache. To fix this you must instruct browser to not cache the restricted pages,this way browser is forced to request the page from the server instead of from the cache. You can do this using a Filter which sets the necessory response headers in the doFilter() method and map to URL pattern.

# POTENTIAL SENSITIVE DATA VISIBLE AFTER IDLE SESSION TIMEOUT  / PAGE DO NOT REFRESH AFTER IDLE SESSION TIMEOUT

- Web app does not redirect user to login screen after idel time more than 30 min, this mauy allow information to be left on screen if user walks away

* Remediation

- Application should use Client side javascript / set Timeout function or a meta tags to refresh browser screen to ensure an idle session does not leave sensitive information on screen for an extended period of time, user should be redirected automatically to login page.

# INSUFFICIENT SESSION EXPIRATION                          

senerio-1

The auth token used after lougout makes login successful even withjout provideing credentials, if we pass any previous request it gives 200 response.

senerio-2

Endpoints of app were found vulnerable to session cookie reuse after the logout procedures was completed,  it is found that the logout functionality did not invalidate the users present cookies web site permits the attacker to reuse old session credentials or session IDs for authorization

* Remediation

Web application should invalidate session after a predefined idle time has passed, the logout function should be prominently visible to user, explicitly invalidate a users session and disallow reuse of session token.

senerio-3

In XYZ application a user's session can be continued again even after the session time out.

After leaving app idle it prompts that app will timeout in 20 min, after 30 min it prompts that session has expired and close the window, At this stage we click No to not close window

we intercept the request and response, we can note that app calls 'terminatesession.jsp' when session is suppose to expire, the session tokens are JSESSION ID and Ltpatoken2, Inspite call terminatesession.jsp the session does not expire and still works, even when we make new request it works with same cookies

* Remediation

- Kill all session cookies values for the user on server side as soon as a user logs out of application

- Deleting cookies only at browser level is not the soluition.

- Always specify session expiration date, make sure it is not too long and that user can reset the session using log off functionality.

- Upon idle timeout browser should automatically refresh to logout URL.

# PERMITTING CONCURRENT SESSIONS                           

* Remediation

If this is really a buisness case then Allow concurrent sessions but notify the user if another session is open, becuase if the session cookie can be sent to another user and be used to impersonate legit user

Else do not allow concurrent sessions. Solutions include but are not limited to list below

- Generating a new session identifier for each page and destroying each session identifier after it is used.

- Tracking user sessions with a database and logging out users with more than one sesion active.  

********************************************************************************************************************************************************

# PRIVACY VIOLATION : AUTOCOMPLETE FEATURE 

Autocomplete is permitted by an application, browser will store the sensitive information and information is higly susceptible to unauthorized disclosure in the event that an  attacker or instance of malicious software is able to access users pc or browser.

* Remediation

The use of AutoComplete can be disabled by setting the AUTOCOMPLETE attribute of HTML Input Tags to "OFF".

********************************************************************************************************************************************************

# IMPROPER AUTHENTICATION  



# HTTP BASIC AUTHENTICATION USED 

Upon initial request to the internal site the application request credentials via HTTP Basic Authentication.

* Remediation

- In a token (session id) based systemm, authentication credentials are collected in HTML form and credentials are passed in HTTPS body and not the HTTPs Headers. Also the credentials are carries only once to acquire a valid session token. The password is not repeateadly send in HTTPs request as in Basic Authentication or a Digest Autothentication

- The attack window for a token-based system is very less as session id is set to expire

- In a token-based system, session management is pretty secure as there is a proper life cycle followed for the session token.

- for these reasons ensure tht a token-based system is used to transport authentication credentials

********************************************************************************************************************************************************

# VERTICAL/HORIZONTAL PRIVILAGE ESCLATION

# INCORRECT AUTHORIZATION CHECKS                           

Basically vertical privilage esclation it is, ie a user is authrised to more than required

* Remediation

# IMPROPER ACCESS CONTROL FORCED BROWSING 

# INSUFFICIENT AUTHORIZATION                               

senerio1
we are abele to see edit/approve/reject greyed out buttons, when we inspect element for approve button, we see an anchor tag with href="javascript:void(0);", when we change it to href="javascript:doApprove();" we are able to click and approve functionality.

senerio2 
Forced Browsing - By directly accessing privilages url which user does not have access to, we are able to access it

* Remediation

To prevent forced browsing, ensure user's access rights are restricted to the correct privilaged level, and not just by pages availible to the user in interface, The privilage esclation attack can be mitigated by following ways:

- Do not trust user data for access control decision

- Do not make access control decisions in javascript

- Do not depend on the order of values sent from the client.

- Never make authorization decisions based soley on hidden fields, cookie values, form parameters, URL parameters, anything else from request.

*********************************************************************************************************************************************************

# SECURITY MISCONFIGURATION-COOKIE SCOPED TO PARENT DOMAIN 

It has been found that ETf app is issuuing cookies such as PD-ID blah blah which are scoped to a parent domain (;Domain=.dtcc.com;). Browsers automatically submit the cookie in requests to in-scope domains and those domains will also be abel to access the cookie via javascript.

If the cookie is scoped to a parent domain then that cookie will be accessible by parent domain and also by any other subdomains of parent domains.
If the cookie contains sensitive data such as session token then this data may be accessible by less trusted apps residing at those domain leading to security compromise

* Remediation

- remove the domain attributre in cookie which has parent domain

- if cant remove then review domain and subdomins

*********************************************************************************************************************************************************

# IMPROPER INPUT VALIDATION                               

xml injected dsata can be seen

*********************************************************************************************************************************************************

# HOST HEADER POISONING                                         

inject any host and we can see the user is redirected 301 to malicious site evil.com/gcuadmin..

*********************************************************************************************************************************************************

# INFORMATION LEAKAGE                                           

# INFORMATION EXPOSURE THROUGH QUERY STRINGS IN GET REQUEST    

* Remediation

When sensitive information is sent use POST method

# POTENTIAL SENSITIVE DATA VISIBLE AFTER IDLE SESSION TIMEOUT   

*********************************************************************************************************************************************************

# MISSING HTTP-STRICT TRANSSPORT SECURITY HEADER                

HSTS is a web application does not implement HSTS header properly by setting "max-age=0" which effectively disables the HSTS feature when browser reeives this response

* Remediation

- Transparently redirect users to this secure connection regardless of how they come to the site by sending a 301 HTTP Response.

- Make sure that all user's sensetive session information uses only secure connection by adding a secure keyword when sestting cookies.

- Send a Strict -Transport-Security header to make sure users always visit the site over HTTPS, and never accidently open a window of opportunity for active network acctakers.

*********************************************************************************************************************************************************

# CROSS SITE SCRIPTING - REFLECTED 

* Remediation

- Never insert untrusted data excepts in allowed locations

- HTML Escape before inserting untrusted data into HTML Element Content

- Attribute Escape before inserting untrusted data into HTML Coomon Attributes

- CSS Escape and Strictly Validate Before inserting untrusted data into HTML style property values

- URL Escape before inserting untrusted data into HTML URL parameter values

- Use HTTPOnly cookie flag

- Use the following output encoding rules

    - HTML Entity Encoding - convert & to &amp;, < to &lt; > to &gt;, " to &quot; ' to &#x27;, / to &#x2F;

    - HTML Attribute Encoding - except alphanumeric characters, escape all other characters with the HTML entity &#xHH; format, including spaces. (HH = 
                                Hex value)

    - URL Encoding - replace unsafe ASCII characters with a "%" followed by two hexadecimal digits representing them.

    - Javascript Encoding - except alphanumeric characters, escape all other characters with the \uXXX unicode escaping format (X = Integer)

    - CSS Hex Encoding - except alphamueric characters, escape all other characters with the \XX or \XXXXXX escaping format (X = integer)

*********************************************************************************************************************************************************

# BUISSINESS LOGIC ABUSE 

senerio1
app allows user to to save/submit invalid sensetive data (can be done by intercepting req if not allowed directly)

*********************************************************************************************************************************************************

# BLIND SQL INJECTION

* Remediation

- Validate input - the vast majority of SQL injection attacks can be prevented by properly validing user input for both type and format. The best method 
                   of doing this is via "whitelisting". This is defined as only accepting specific account numbers or specific account types, or only alphanumneric are allowed, Many developer wihh try to validate input via "blacklisting" characters or escaping them which could lead to problems.

- Parametrized Queries - SQL injection arises from an attackers manipulation of query data to modify query logic. The best method pf preventing SQL 
                         injection attacks is there by to seperate the logic of query from its data. This will prevent commands inserted from user input from being executed. The downsize of this approach is that it can have an impact on performnace.

                        
*********************************************************************************************************************************************************

# CROS FRAME SCRIPTING

* Remediation
- X-Frame-Options-Header : deny/same-origin/Allow-from

- Content-Security-Policy: frame-ancestors 'none'/'self'/*.somesite.com ;

- frame busting code , Include a "frame-breaker" script in each page that should not be framed.


    First apply an ID to the style element itself:

    <style id="antiClickjack">
        body{display:none !important;}
    </style>

    Then, delete that style by its ID immediately after in the script:

    <script type="text/javascript">
        if (self === top) {
            var antiClickjack = document.getElementById("antiClickjack");
            antiClickjack.parentNode.removeChild(antiClickjack);
        } else {
            top.location = self.location;
        }
    </script>

The above methodology will prevent a webpage from being framed even in legacy browsers, that do not support the X-Frame-Options-Header.
