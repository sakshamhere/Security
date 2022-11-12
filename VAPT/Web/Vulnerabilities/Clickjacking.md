# What is Clickjacking?
Clickjacking is an interface-based attack in which a user is tricked into clicking on actionable content on a hidden website by clicking on some other content in a decoy website

Historically, clickjacking has been used to perform behaviors such as boosting "likes" on a Facebook page. 

# Example
A web user accesses a decoy website (perhaps this is a link provided by an email) and clicks on a button to win a prize. Unknowingly, they have been deceived by an attacker into pressing an alternative hidden button and this results in the payment of an account on another site

clickjacking attacks abusing Facebook’s “Like” functionality. Attackers can trick logged-in Facebook users to arbitrarily like fan pages, links, groups, etc

# CSRF vs Clickjacking

Protection against CSRF attacks is often provided by the use of a CSRF token: a session-specific, single-use number or nonce. Clickjacking attacks are not mitigated by the CSRF token as a target session is established with content loaded from an authentic website and with all requests happening on-domain. CSRF tokens are placed into requests and passed to the server as part of a normally behaved session. The difference compared to a normal user session is that the process occurs within a hidden iframe

There is a very important distinction between them: a clickjacking attack requires the victim to interact with UI elements on a targeted website, whereas CSRF does not inherently require interaction on the victim’s part.

 In a CSRF attack, the attacker doesn’t care about the response at all: the request is the only important thing.

# Burp ClickBandit

Although you can manually create a clickjacking proof of concept as described above, this can be fairly tedious and time-consuming in practice. When you're testing for clickjacking in the wild, we recommend using Burp's Clickbandit tool instead. This lets you use your browser to perform the desired actions on the frameable page, then creates an HTML file containing a suitable clickjacking overlay. You can use this to generate an interactive proof of concept in a matter of seconds, without having to write a single line of HTML or CSS.

# Clickjacking combined with DOM XSS

However, the true potency of clickjacking is revealed when it is used as a carrier for another attack such as a DOM XSS attack. Implementation of this combined attack is relatively straightforward assuming that the attacker has first identified the XSS exploit. The XSS exploit is then combined with the iframe target URL so that the user clicks on the button or link and consequently executes the DOM XSS attack.

# Prevention

Clickjacking attacks are possible whenever websites can be framed. Therefore, preventative techniques are based upon restricting the framing capability for websites

* Frame Busting / Frame Breaking scripts:

These can be implemented via proprietary browser JavaScript add-ons or extensions such as NoScript. Scripts are often crafted so that they perform some or all of the following behaviors:

- check and enforce that the current application window is the main or top window,
- make all frames visible,
- prevent clicking on invisible frames,
- intercept and flag potential clickjacking attacks to the user.

* X-Frame-Options       - The X-Frame-Options HTTP response header can be used to indicate whether or not a browser should be allowed 
                          to render a page in a <frame>, <iframe>, <embed> or <object>. 
                          Sites can use this to avoid click-jacking attacks, by ensuring that their content is not embedded into other sites.
    X-Frame-Options: deny
    X-Frame-Options: sameorigin
    X-Frame-Options: allow-from https://normal-website.com\

* Content Security Policy - Content Security Policy (CSP) is a detection and prevention mechanism that provides mitigation against
                            attacks such as XSS and clickjacking and data injection attacks. CSP is usually implemented in the web server as a return header of the form:

    Content-Security-Policy: policy

frame-ancestors - The recommended clickjacking protection is to incorporate the frame-ancestors directive in the application's Content 
                  Security Policy
    Content-Security-Policy: frame-ancestors 'none';                similar in behavior to the X-Frame-Options deny directive
    Content-Security-Policy: frame-ancestors 'self';                equivalent to the X-Frame-Options sameorigin directive.
    Content-Security-Policy: frame-ancestors 'normal-website.com;';  framing can be restricted to named sites:

* SameSite Cookies attribute

The SameSite cookie attribute defined in RFC 6265bis is primarily intended to defend against cross-site request forgery (CSRF); however it can also provide protection against Clickjacking attacks.

Cookies with a SameSite attribute of either strict or lax will not be included in requests made to a page within an <iframe>.

This means that if the session cookies are marked as SameSite, any Clickjacking attack that requires the victim to be authenticated will not work, as the cookie will not be sent

If the Clickjacking attack does not require the user to be authenticated, this attribute will not provide any protection.


* Window.confirm() Protection

In scenarios where content must be frameable, then a window.confirm() can be used to help mitigate Clickjacking by informing the user of the action they are about to perform.
Invoking window.confirm() will display a popup that cannot be framed

For example:

<script type="text/javascript">
   var action_confirm = window.confirm("Are you sure you want to delete your youtube account?")
   if (action_confirm) {
       //... Perform action
   } else {
       //... The user does not want to perform the requested action.`
   }
</script>