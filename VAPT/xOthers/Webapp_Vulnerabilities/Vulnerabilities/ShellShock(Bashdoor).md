https://owasp.org/www-pdf-archive/Shellshock_-_Tudor_Enache.pdf

https://unix.stackexchange.com/questions/157381/when-was-the-shellshock-cve-2014-6271-7169-bug-introduced-and-what-is-the-pat/157495#157495

 https://subscription.packtpub.com/book/networking-&-servers/9781784392918/7/ch07lvl1sec73/executing-commands-with-shellshock

https://blog.cloudflare.com/inside-shellshock/

Shellshock is effectively a Remote Command Execution vulnerability in BASH

The vulnerability relies in the fact that BASH incorrectly executes trailing commands when it imports a function definition stored into an environment variable

Shellshock (also called Bashdoor) is a bug that was discovered in the Bash shell in September 2014, allowing the execution of commands through functions stored in the values of environment variables. 

When a web server receives a request for a page there are three parts of the request that can be susceptible to the Shellshock attack: the request URL, the headers that are sent along with the URL, and what are known as "arguments" (when you enter your name and address on a web site it will typically be sent as arguments in the request).

https://unix.stackexchange.com/questions/157329/what-does-env-x-command-bash-do-and-why-is-it-insecure

Payload = "() {:;}; Malcious command here"


# Shellshock Attack on a remote web server

CGI runs bash as their default request handler and this attack does not require any authentication that’s why most of the attack is taken place on CGI pages to exploit this vulnerability.

> in exploitation section from here