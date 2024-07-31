# What is SSRF?     https://www.youtube.com/watch?v=ih5R_c16bKc

SSRF is vulnerability wherer attacker tries to abuse functionality on server to make request to an unintended location or to read or manupilate internal resources.

SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. 

It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL).

As modern web applications provide end-users with convenient features, fetching a URL becomes a common scenario. As a result, the incidence of SSRF is increasing. Also, the severity of SSRF is becoming higher due to cloud services and the complexity of architectures

# Types of SSRF

* Regular / In Band

This is when we as an attacker can temper with the URL, and the reponse to the url gets displayed to us in the application

* Blind / Out-of-Band (OAST)

In this the application does not provide the response back from our request, even though the application is vulnerable

You need to force the application to make a DNS or an HTTP request to an attacker controlled server like Burp Collaborater, if you get response then app is vulnerable to SSRF

# Impact

Impact depends on the functionality being exploited

* Sensitive information disclosure - We can perform sensitive functionality in services hosted in internal network
* Denial of Service
* We can get remote code execution
* We can Port scan the network

# How to find SSRF vulnerability

Black Box Testing

Map the application- Identify any request parameters that contains hostnames, IP address, or full URLs

Fuzzing app with SSRF payload - For each request parameter, modify its value to specify an alternative resource and observe how the application reponsds
    - if there is a defence in place, attempt to circumvent it using known techniques

For Blind SSRF
- for each request parameter modify its value to a server on the internet that you control and monitor the server for incoming request.

White Box Testing

- Review source code and identiy all request parameters that accepts URLs

- Determine what URL parser is being used and if it can be passed, similary what additional defences are there which can be bypassed

# Exploiting SSRF

If the application allows for user-supplied arbitrary URLs, try the following attack

- Determine if a port number can be specified
- If successful, attempt to port-scan the internal network using Burp Intruder
- Attempt to connect to other services on the loopback address 

If the application does not allow for arbitrary user-supplied URLs, try to bypass defences using the following techniques

- use diffrent encoding schemes if internal IP is in blacklist
    - decimal encoded version of 127.0.0.1 is 2130706433
    - 127.1 resolves to 127.0.0.1
    - octal representation of 127.0.0.1 is 017700000001



# Defendces / Preventions

Defence in Depth approach:

- Application Layer Defences

    - Sanitize and validate all client-supplied input data
    - Enforce the URL schema, port and destination with whitelist
    - Do not send raw responses to clinets
    - Disable HTTP redirect ions

Note - you should not mitiagte SSRF vulnerabilities using deny list or regular expressions, as blacklist can be bypassed by octal,decimal representations and may others

- Network Layer Defences

    - Network Layer Segmentation - Segment remote resource access functionality in seperate networks to reduce impact of SSRF
    - Enforce "deny by default" firewall policies or network access control rules to block all essential intranet traffic
    - Log all accepted and blocked network flows on firewalls (see A09:2021-Security Logging and Monitoring Failures).


# Example Attack Scenarios
Attackers can use SSRF to attack systems protected behind web application firewalls, firewalls, or network ACLs, using scenarios such as:

* Scenario #1: Port scan internal servers – 

If the network architecture is unsegmented, attackers can map out internal networks and determine if ports are open or closed on internal servers from connection results or elapsed time to connect or reject SSRF payload connections.

* Scenario #2: Sensitive data exposure – 

Attackers can access local files or internal services to gain sensitive information such as file:///etc/passwd and http://localhost:28017/.

* Scenario #3: Access metadata storage of cloud services – 

Most cloud providers have metadata storage such as http://169.254.169.254/. An attacker can read the metadata to gain sensitive information.

* Scenario #4: Compromise internal services – 

The attacker can abuse internal services to conduct further attacks such as Remote Code Execution (RCE) or Denial of Service (DoS).

# CWE
This is itself a CWE