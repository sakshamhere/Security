https://owasp.org/www-community/attacks/Reverse_Tabnabbing

https://book.hacktricks.xyz/pentesting-web/reverse-tab-nabbing

https://www.youtube.com/watch?v=uOrHY5kRrP8

Reverse tabnabbing is an attack where a page linked from the target page is able to rewrite that page, for example to replace it with a phishing site. As the user was originally on the correct page they are less likely to notice that it has been changed to a phishing site, especially if the site looks the same as the target. If the user authenticates to this new page then their credentials (or other sensitive data) are sent to the phishing site rather than the legitimate one.

# When a user clicks on the Vulnerable Target link/button then the Malicious Site is opened in a new tab (as expected) but the target site in the original tab is replaced by the phishing site

Attacker will use link with _blank attribute to open it in new tab and his link will take it to his site where he has code to modify the location of original site where victim found the link, as soon as victim clicks on link he is taken to new tab and at the same time the orisgnal site it now changed to a phishing site.


link  - <a href="http://192.168.46.129:8000/poc.html" target="_blank">click</a>


attacks site page code
<html>

<script>console.log(window.opener.location.replace("https://phishingsite.com"))</script>

<script>console.log(window.opener)</script>
</html>

# Prevent

1. Add the `rel=“noopener noreferrer”` Attribute to the Links

Add rel=”noopener noreferrer” to every <a> element that has the target set to “_blank”. Noopener ensures that the linked page does not have access to window.opener from the linking page. Noreferrer makes sure that the request referrer header is not being sent. Thus, the destination site will not see the URL the user came from.

2. Implement the `Cross-Origin-Opener-Policy` Header

There is a new browser security feature called cross-origin-opener-policy (COOP). This feature can help prevent an attack where a malicious website calls “window.open” on the victim’s website and then redirects the victim to the attacker’s site.

Return the following HTTP response header from webserver. Browsers that support COOP will process-isolate the document, and attackers can’t access the victim’s site anymore:

Cross-origin-opener-policy: same-origin


3. `Sandbox` the Frames

Sandbox the frames to prevent the tabnabbing attack from websites loaded in an iframe. Sandboxing can be achieved by setting the attribute “sandbox” as:

<iframe sandbox=”allow-scripts allow-same-origin” src=”https://www.example.com”></iframe>

The sandbox attribute controls many things by default. Mainly, it prevents the framed website from redirecting its parent site.


NOTE - Nowadays, browsers support multiple security features to prevent this kind of attack. However, the developer has to take preventive measures by implementing these security controls to protect legitimate users.