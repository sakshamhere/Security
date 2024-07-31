# SOP, CORS         https://www.youtube.com/watch?v=t5FBwq-kudw

SOP (Same Origin Policy) - SOP is built in policy that is enforced by browsers to control access to data between web applications.

For Example there are two applications  
                                        Bank application   <--->   Shopping applicatin
                        
by default these two appilcation is limited, the banking app can make request like submiting a form to shopping application, however it cannot read the response from the application

This is something implemented by default in all browsers for security reasons to avoid applications attacking each other

Origin - origin is defined by the protocol, domain and the port of URL used by request.

NOTE 

- SOP does not prevent writing between application but it prevents reading between web applications
- Access is determined based on origin

So if shopping application request to bank application the bank app will reject the request because the request is from diffrent origin


CORS (Cross Origin Resource Sharing)
CORS is a mechanism that uses HTTP headers to define origins that broswer will permit to load resources from.

If origin A request resource from origin B and B uses CORS to allow it then A will be able to acess

Cross-origin resource sharing uses " HTTP Headers " to define origin that browser can permit

CORS makes use of 2 HTTP header:
    -  Access-Control-Allow-Origin
    -  Access-Control-Allow-Credentials
    
# The Access-Control-Allow-Origin response header

The Access-Control-Allow-Origin response header indicates whether the response can be shared with requesting code by given origin

For example origin A wants to access resource from origin B with request

        GET /home.aspx HTTP/1.1
        HOST: domain-b.com
        Origin: domain-a.com

Then Origin B response would be

        HTTP/1.1 200 OK
        Access-Control-Allow-Origin: domain-a.com

Since the browser see the CORS header indincating to allow domain-a.com to read hence it will be allowed

Syntex:

- The Access-Control-Allow-Origin: *            (Allows all site/domains)
- The Access-Control-Allow-Origin: <origin>     (Allow only single origin, NOTE- we cant add multiple)   
- The Access-Control-Allow-Origin: null


* The Access-Control-Allow-Origin allows us to only access public pages in website, in order to access authenicated pages we need to use The Access-Control-Allow-Credential

# Access-Control-Allow-Credential response header

Access-Control-Allow-Credential header allows credentials like cookies, authorization header, tls client certificates to be included in cross-origin request

For example origin A wants to access resource from origin B with request

Request
        Get /accountDetails HTTP/1.1
        HOST: domain-b.com
        Cookie: session=iwdsdihjieuyrbjfcsnbjhfsbiure
        Origin: domain-a.com

Response from B

        HTTP/1.1 200 OK
        Access-Control-Allow-Origin: domain-a.com
        Access-Control-Allow-Credentials: true

basically it says that you are allowed to pass credentials in request.


NOTE - If the server is configured Access-Control-Allow-Origin with (" * ")  as value, then use of credential is not allowed

# CORS Vulnerabilities

- CORS vulnerabilities arise from CORS misconfigurations on the developers part which causes security risk

# The Problem

We saw above that "Access-Control-Allow-Origin" either allows all * or only single domain, however in real world an application needs to communicate with various domains for proper functioning.

Now since we want multiple domains to get whitelisted, thats where " DYNAMIC GENRATION " comes to play

# Dynamic Generation

In order to trust multiple domains we use dynamic generation, but CORS vulnerability arise from the flaws in the way the dynamic generation is implemented 

- Use Client-specified origin header in Server-generated Access-Control-Allow-Origin
    - This simply extracts the domain from request and puts that in response header, this is similar to "*" and will allow all domains

- Error Parsing Origin header
    - Granting access to all domains that end in specific string
        * Example: bank.com
        * Bypass: maliciousbank.com
    - Granting access to all domains that begin with specific string
        * Example: bank.com
        * Bypass: bank.com.malicious.com

- Whitelisted null origin value
    - This is again equivalent to using wild card ie * because if we tweak our malicious script and make it run in sandbox iframe it will appear as if it is coming from origin null and will allow resources to be accessed
    - This is more dangerous than using " * " because in wildcard we have rule that if " * " is used than you can't send credentials (like auth token,cookies,tls cert etc ), however the null origin value dosent abide these rules, you are allowed to send credentials

# Impact

- Sensitive Information Disclosure

# Finding CORS vulnerabilities

Black Box Testing
 - Map the applications
    - go through all the pages accessible, try to see if there are any CORS headers used by application
    - if we do not found CORS headers that dosent mean application dosent use it as it may use dynamic generation 
        - Test for dynamic genration
            - Check for all three conditions discussed above for dynamic generation
            * Does it reflect the user-supplied ACAO header?
                - Intercept request in burp and change origin in header to random value and see if its reflected back
            * Does it only validate on the start/End of a specif string using regex or something?
                - try to add letters in beginning or end and bypass, if it accepts that means we can register that domain
            * Does it allow null origin?
            * Does it restricts the protocol?
                - try using HTTP if it uses HTTPs
            * Does it allow credentials?

- Once you determine that there is CORS vulnerability exist, review the application's functionality to determine how you can prove impact

White Box testing

- Identify the framework/technologies that is being used by the application
- Find out how this specific technology allows for CORS configuration
- Review code to identify any misconfigurations in CORS rules

# Prevent

- Proper configuratoin of cross-origin requests
- Only allow trusted sites
- Avoid whitelisting the null origin
- Avoid wildcards in internal network