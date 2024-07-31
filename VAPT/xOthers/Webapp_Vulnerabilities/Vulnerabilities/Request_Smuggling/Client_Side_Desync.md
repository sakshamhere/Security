https://portswigger.net/web-security/request-smuggling/browser/client-side-desync

A regular request smuggling desynchronize the connection between a front-end and back-end server. but this attack makes the victim's web browser desynchronize its own connection to the vulnerable website.

 Web servers can sometimes be encouraged to respond to POST requests without reading in the body. If they subsequently allow the browser to reuse the same connection for additional requests, this results in a client-side desync vulnerability.

In high-level terms, a CSD attack involves the following stages:

    The victim visits a web page on an arbitrary domain containing malicious JavaScript.

    The JavaScript causes the victim's browser to issue a request to the vulnerable website. This contains an attacker-controlled request prefix in its body, much like a normal request smuggling attack.

    The malicious prefix is left on the server's TCP/TLS socket after it responds to the initial request, desyncing the connection with the browser.

    The JavaScript then triggers a follow-up request down the poisoned connection. This is appended to the malicious prefix, eliciting a harmful response from the server.

As these attacks don't rely on parsing discrepancies between two servers, this means that even single-server websites may be vulnerable. 


Note

For these attacks to work, it's important to note that the target web server must not support HTTP/2. Client-side desyncs rely on HTTP/1.1 connection reuse, and browsers generally favor HTTP/2 where available.

One exception to this rule is if you suspect that your intended victim will access the site via a forward proxy that only supports HTTP/1.1.
