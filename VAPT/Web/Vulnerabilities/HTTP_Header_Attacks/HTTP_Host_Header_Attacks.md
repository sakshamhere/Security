# What and Why is HTTP Host Header

The HTTP Host header is a mandatory request header as of HTTP/1.1. The purpose of the HTTP Host header is to help identify which back-end component the client wants to communicate with, If requests didn't contain Host headers, or if the Host header was malformed in some way, this could lead to issues when routing incoming requests to the intended application.

Historically, this ambiguity didn't exist because each IP address would only host content for a single domain.

But Now!, due to the ever-growing trend for cloud-based solutions and outsourcing much of the related architecture, it is common for multiple websites and applications to be accessible at the same IP address

When multiple applications are accessible via the same IP address, this is most commonly a result of one of the following scenarios.

- Virtual hosting: when a single web server hosts multiple websites or applications

- Routing traffic via an intermediary: when websites are hosted on distinct back-end servers, but all traffic between the 
                                       client and servers is routed through an intermediary system. This could be a simple load balancer or a reverse proxy server of some kind.

HTTP Host header solve this problem In both of these scenarios, When a browser sends the request, the target URL will resolve to the IP address of a particular server. When this server receives the request, it refers to the Host header to determine the intended back-end and forwards the request accordingly.

# What and Why HTTP Host header attack

HTTP Host header attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way.

If the server implicitly trusts the Host header, and fails to validate or escape it properly, an attacker may be able to use this input to inject harmful payloads that manipulate server-side behavior. Attacks that involve injecting a payload directly into the Host header are often known as "Host header injection" attacks

Off-the-shelf web applications typically don't know what domain they are deployed on unless it is manually specified in a configuration file during setup. When they need to know the current domain, for example, to generate an absolute URL included in an email, they may resort to retrieving the domain from the Host header:

<a href="https://_SERVER['HOST']/support">Contact support</a>

As the Host header is in fact user controllable, this practice can lead to a number of issues. If the input is not properly escaped or validated, the Host header is a potential vector for exploiting a range of other vulnerabilities

HTTP Host header vulnerabilities typically arise due to the flawed assumption that the header is not user controllable.

This creates implicit trust in the Host header and results in inadequate validation or escaping of its value, even though an attacker can easily modify this using tools like Burp Proxy.

Even if the Host header itself is handled more securely, depending on the configuration of the servers that deal with incoming requests, the Host can potentially be overridden by injecting other headers.

In fact, many of these vulnerabilities arise not because of insecure coding but because of insecure configuration of one or more components in the related infrastructure

# Impact
Host header is a potential vector for exploiting a range of other vulnerabilities, most notably:

- Web cache poisoning
- Routing-based SSRF
- Classic server-side vulnerabilities, such as SQL injection
- Business logic flaws in specific functionality

# Testing for HTTP Host header attack

To test whether a website is vulnerable to attack via the HTTP Host header, you will need an intercepting proxy, such as Burp Proxy, and manual testing tools like Burp Repeater and Burp Intruder.

In short, you need to identify whether you are able to modify the Host header and still reach the target application with your request. If so, you can use this header to probe the application and observe what effect this has on the response

1. Supply an arbitrary Host header
2. Check for flawed validation
3. Send ambiguous requests
4. Inject host override headers

* Supply an arbitrary Host header

The first step is to test what happens when you supply an arbitrary, unrecognized domain name via the Host header.

-   Sometimes, you will still be able to access the target website even when you supply an unexpected Host header. This could 
    be for a number of reasons. For example, servers are sometimes configured with a default or fallback option in case they receive requests for domain names that they don't recognize. If your target website happens to be the default, you're in luck. In this case, you can begin studying what the application does with the Host header and whether this behavior is exploitable.

-   While on the other hand The Host header is such a fundamental part of how the websites work, tampering with it often means 
    you will be unable to reach the target application at all. The front-end server or load balancer that received your request may simply not know where to forward it, resulting in an "Invalid Host header" error of some kind. This is especially likely if your target is accessed via a CDN. In this case, you should move on to trying some of the techniques

* Check for flawed validation

-   Instead of receiving an "Invalid Host header" response, you might find that your request is blocked as a result of some 
    kind of security measure. 
    
    For example, some websites will validate whether the Host header matches the SNI from the TLS handshake (Server Name Indication (SNI) is an extension to the TLS protocol. It allows a client or browser to indicate which hostname it is trying to connect to at the start of the TLS handshake.). This doesn't necessarily mean that they're immune to Host header attacks.

    We should try to understand how the website parses the Host header. This can sometimes reveal loopholes that can be used to bypass the validation. For example:

        - some parsing algorithms will omit the port from the Host header, meaning that only the domain name is validated. If you are also able to supply a non-numeric port, you can leave the domain name untouched to ensure that you reach the target application, while potentially injecting a payload via the port.
            GET /example HTTP/1.1
            Host: vulnerable-website.com:bad-stuff-here

        - We may be able to bypass the validation entirely by registering an arbitrary domain name that ends with the same sequence of characters as a whitelisted one:
            GET /example HTTP/1.1
            Host: notvulnerable-website.com

        - We could take advantage of a less-secure subdomain that you have already compromised:
            GET /example HTTP/1.1
            Host: hacked-subdomain.vulnerable-website.com

        - Using domain-validation flaws as used to bypass CORS and SSRF here in such a way that our supplied host is validated successfully using conditions like
            -  suppose an application grants access to all domains beginning with, ending with original domain

* Send ambiguous requests

The code that validates the host and the code that does something vulnerable with it often reside in different application components or even on separate servers. 

By identifying and exploiting discrepancies in how they retrieve the Host header, you may be able to issue an ambiguous request that appears to have a different host depending on which system is looking at it.The following are just a few examples 

    - Inject duplicate Host headers
        One possible approach is to try adding duplicate Host headers. Admittedly, this will often just result in your request being blocked. However, as a browser is unlikely to ever send such a request, you may occasionally find that developers have not anticipated this scenario. In this case, you might expose some interesting behavioral quirks.

        Different systems and technologies will handle this case differently, but it is common for one of the two headers to be given precedence over the other one, effectively overriding its value.

        When systems disagree about which header is the correct one, this can lead to discrepancies that you may be able to exploit.

        GET /example HTTP/1.1
        Host: vulnerable-website.com
        Host: bad-stuff-here

        Let's say the front-end gives precedence to the first instance of the header, but the back-end prefers the final instance. Given this scenario, you could use the first header to ensure that your request is routed to the intended target and use the second header to pass your payload into the server-side code.
    
    - Supply an absolute URL
        Although the request line typically specifies a relative path on the requested domain, many servers are also configured to understand requests for absolute URLs.

        The ambiguity caused by supplying both an absolute URL and a Host header can also lead to discrepancies between different systems. Officially, the request line should be given precedence when routing the request but, in practice, this isn't always the case. 
        
        You can potentially exploit these discrepancies in much the same way as duplicate Host headers.

        GET https://vulnerable-website.com/ HTTP/1.1
        Host: bad-stuff-here

        Note that you may also need to experiment with different protocols. Servers will sometimes behave differently depending on whether the request line contains an HTTP or an HTTPS URL.

    - Add line wrapping
        You can also uncover quirky behavior by indenting HTTP headers with a space character. Some servers will interpret the indented header as a wrapped line and, therefore, treat it as part of the preceding header's value. Other servers will ignore the indented header altogether.

        For example, consider the following request:

        GET /example HTTP/1.1
            Host: bad-stuff-here
        Host: vulnerable-website.com

        The website may block requests with multiple Host headers, but you may be able to bypass this validation by indenting one of them like this. If the front-end ignores the indented header, the request will be processed as an ordinary request for vulnerable-website.com. Now let's say the back-end ignores the leading space and gives precedence to the first header in the case of duplicates. This discrepancy might allow you to pass arbitrary values via the "wrapped" Host header.

        Due to the highly inconsistent handling of this case, there will often be discrepancies between different systems that process your request. 

    - Other techniques
        - HTTP request smuggling

* Inject host override headers

Even if you can't override the Host header using an ambiguous request, there are other possibilities for overriding its value while leaving it intact. This includes injecting your payload via one of several other HTTP headers that are designed to serve just this purpose

As we've already discussed, websites are often accessed via some kind of intermediary system, such as a load balancer or a reverse proxy. In this kind of architecture, the Host header that the back-end server receives may contain the domain name for one of these intermediary systems. This is usually not relevant for the requested functionality.

To solve this problem, the front-end may inject the " X-Forwarded-Host header ", containing the original value of the Host header from the client's initial request. For this reason, when an X-Forwarded-Host header is present, many frameworks will refer to this instead.

You can sometimes use X-Forwarded-Host to inject your malicious input while circumventing any validation on the Host header itself.

    GET /example HTTP/1.1
    Host: vulnerable-website.com
    X-Forwarded-Host: bad-stuff-here

Although X-Forwarded-Host is the de facto standard for this behavior, you may come across other headers that serve a similar purpose, including: X-Host, X-Forwarded-Server , X-HTTP-Host-Override, Forwarded

In Burp Suite, you can use the Param Miner extension's "Guess headers" function to automatically probe for supported headers using its extensive built-in wordlist.

From a security perspective, it is important to note that some websites, potentially even your own, support this kind of behavior unintentionally. This is usually because one or more of these headers is enabled by default in some third-party technology that they use                                                    

# Exploiting HTTP Host header attack

Once you have identified that you can pass arbitrary hostnames to the target application, you can start to look for ways to exploit it.

some examples of common HTTP Host header attacks that you may be able to construct.

-   Password reset Poisoning
    - Password reset Poisoning via Dangling markup injection