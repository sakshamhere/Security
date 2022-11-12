* Metasploitable - 

username - msfadmin

A vulnerable linux distribution, this OS contains a number of Vulnerabilities, it is designed for pentesters to try  and hack it.

This is going to be victim which we will try to hack

it is a linux VM that contains applications that are typically used in Servers it also contains a number of Web Applications and act exactly like normal web applications and use the same services used by normnal severs and normal web applications

A vulnerabel Servier machine so we can test server side attacks and other attacks

# How to Hack Website??

1. Web application pentesting - Exploit the Web Application 
2. Server side attacks - Exploit programs installed on the OS and applications on the web server on which website is running
3. Client side attacks - Exploit the humans using social engineering who manage the website or have prvilage access

we will do the Web application pentesting

# Information Gathering

We are going to start with gathering as much info as we can, this includes

- IP address
- Domain name
- Technologies used
- other websites on same server
- Databse used
- DNS records
- unlisted/hidden files, subdir and dir

So first thing we will see is WhoisLookup

# 1.  WhoisLookup - Find the info about the owner of Target

So in general when somone registers his/her domain he has to provide certain details/info, which we can see, we can see a lot of information about our target website

we can get many info like - server type, encryption, Ip address, IP location, IP history, contact, Admin details, Registrar details and more

# 2. Netcraft Site Report - Find the technologies used by the target website

https://sitereport.netcraft.com

Huge amount of info can be found here including some of them found in whoislookup

we can go to explot database and find explot relateed to the technology used by website

# 3. Robtex DNS lookup - get Comphrehensive DNS  information

Robtex.com - Robtex is used for various kinds of research of IP numbers, Domain names, etc


* Discovering websites on the same server

- one server can have many websites, gaining access to one can help gaining access to others

- to find websites on same server use Robtex DNS lookup under the "names pointing to same IP", then search for IP on bing.com (IP ...)

- So if we dont find any vulnerability on one site we can find one on another website on same server, once we have access to web server we have access to all sites on it


* Discovering Subdomain

subdomain.target.com        for ex - mail.google.com

if our target is target.com it is very important to discover all subdomains, because this subdomains can give us various information :

- Discover sensitive data
- Discover new web applications
- Discover web applications components which are still under development or Beta versions
- Increase the Attack Surface

We can do this using " Knockpy " like knockpy xyz.com, and it will list all subdomains

* Discovering Sensitive files and dir

in metasploitable

the web server stuff is stored in var/www

we can see all web applications, now in this mutilidae is a web application is designed to be hacked

mutilidae is just a dir inside web root, inside mutilidae theree are various web files

now there are always some hidden files, to find them we will use tool " dirb "

on our kali machine we will use dirb, we can find details for dirb using man dirb

dirb - it is a web content scanner, it looks for existing and hidden web objects, it basically works by launching dictionary based attack against web server and analyzing the response.

it requires a wordlist file, by default it uses a wordlist file usr/share/dirb/wordlists/common.txt


" Maltego " - Maltego is an open source intelligence and forensics application. It will offer you timous mining and gathering of information as well as the representation of this information in a easy to understand format

We can discover - servers, Domains, files, websites, Hosting providers, Emails


# File Upload Vulnerbilities

So for example if target computer understands PHP then we can upload any php file or a php shell and get full control over the target computer

" Weevely " - tool that generates php shells and allow us to gains access and do a number of cool things on the target computer

we can use metasploit 
so we can upload anything but since we are doing web pentesting weevly is good tool to generate php shell payload

1. Generate backdoor            weevely generate [password] [filename]
2. Upload generarted file
3. Connect to it                weevely [url to file] [password]


# Intercepting Requests
  
So in Case of GET request we can see and modify URL, but in case of POST request we cant see it or modify as they are not shown in URL

Another challange is that a lot of website are and will use security,filters and client side code so the request will be modified before it will be sent

So the best way to intercept the request is using a Proxy in our case " Burp Proxy " which is part of popular pentest tool Buip Suite

So the request from us will go to buip instead of web server direclty, buirp will analyze all filter and client code modications performed by site to the request, so we will be able to see the request after the client side code has been applied.

so we will be able to bypass all filters by intercepting the request, then further we send it to web server and it then revert to us


# Code Execution Vulnerabilities

# Local File Inclusion (LFI)

LFI vulnerabilities allows you to read any file that is within the same server, so even if the file is outside the var/www we will abel to read it.

so if user is storing some sort of important file ex password file then we will be able to read it

# Remote File Inclusion

Similar to local file incluision, but here we can include files from outside to target computer and execute them


# SQL Injection Vulnerabilities

SQL injections can be used as file upload vulnerabilities as well as file inclusion vulnerbilities
Exploit Database -  Offensive security exploit Database Archive


https://www.exploit-db.com/