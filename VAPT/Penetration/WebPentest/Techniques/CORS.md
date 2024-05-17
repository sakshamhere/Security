https://www.freecodecamp.org/news/exploiting-cors-guide-to-pentesting/

# the search functionality in Burp Suite to search for the headers quickly.

# Reflected Origins
both Access-Control-Allow-Origin:(your supplied origin) and Access-Control-Allow-Credentials: true should be there
However, the risk is low if passing credentials is not allowed, as the browser will not process the responses from authenticated requests.

# Modified Origins
adding a prefix or suffix to the metrics.com domain would be something like attackmetrics.com or metrics.com.attack.com is allowed.
The risk of this misconfiguration is considered high if the domain allows for passing credentials with the Access-Control-Allow-Credentials header set to true. 

# Trusted subdomains with Insecure Protocol
Set the Origin header to an existing subdomain and see if it accepts it. If it does, it means the domain trusts all its subdomains. This is not a good idea because if one of the subdomains has a Cross-Site Scripting (XSS) vulnerability, it will allow the attacker to inject a malicious JS payload and perform unauthorized actions.

This misconfiguration is considered high risk if the domain accepts subdomains with an insecure protocol, such as HTTP, and the credential header is set to true. Otherwise, it will not be exploitable and would be only a poor CORS implementation.

# Null Origin
Set the Origin header to the null value — Origin: null, and see if the application sets the Access-Control-Allow-Origin header to null. If it does, it means that null origins are whitelisted.
The risk level is considered high if the domain allows for authenticated requests with the Access-Control-Allow-Credentials header set to true.



Exploitable Caeses

- Steal sensitive info, which exist on that vulnerable page 

- XSS

- Remote code Execution (in some case only)

# Cors with reflected XSS to steal sensitive data
https://infosecwriteups.com/chaining-cors-by-reflected-xss-to-steal-sensitive-data-c456e133c10d

https://subdomain.redacted.com/login/mobile?next=javascript:function(){var xhttp=new XMLHttpRequest();xhttp.onreadystatechange=function(){if(xhttp.readyState==4&&xhttp.status==200){alert(xhttp.responseText);}};xhttp.open("GET","https://api.redacted.com/api/v2/user",true);xhttp.withCredentials=true;xhttp.send();})();


https://x.com/Jayesh25_/status/1730131194702958603?s=20

# Jayesh - Here's my approach to finding CORS Issues:

# 1️⃣ Nuclei Scan - 
Identify vulnerable targets with the cors-misconfig.yaml nuclei template using the command nuclei -u http://target -t cors-misconfig.yaml. You can find the template at https://github.com/projectdiscovery/nuclei-templates/blob/ee271cf0eb99d7e90e528d0a45b7dc291c2d7b17/http/vulnerabilities/generic/cors-misconfig.yaml

# 2️⃣ Manual Approach - 
If you're manually hunting on a target app and believe that specific GET/POST/PATCH/PUT/DELETE endpoints were missed by nuclei, add an Origin header to your requests with null or your attacker site. Check the response headers for Access-Control-Allow-Origin: <your_arbitrary_origin> or <null> and Access-Control-Allow-Credentials: true.

# 3️⃣ Craft your POC - 
To ensure your report doesn't get closed as "Informative" or "NA," provide a working PoC. Here's JavaScript code I host on my attacker-controlled server to demonstrate CORS misconfiguration on a sensitive endpoint:

var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if(xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
        alert(xhr.responseText);
    }
}
http://xhr.open('GET', 'http://targetapp/api/v1/user', true); 
xhr.withCredentials = true; 
xhr.send(null);