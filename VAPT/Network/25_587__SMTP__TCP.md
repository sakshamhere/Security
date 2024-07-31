
# Simple Mail Transfer Protocol

SMTP (Simple Mail Transfer Protocol) is a communication protocol that is used for transmission of EMail.

SMTP used `TCP port 25` by default however it can also be configured on `TCP port 465 and 587` If SSL certificate is set.


The `Simple Mail Transfer Protocol (SMTP)` is a protocol for sending emails in an IP network.

It can be used between an email client and an outgoing mail server or between two SMTP servers.

SMTP is often combined with the `IMAP` or `POP3` protocols, which can fetch emails and send emails.

By default, SMTP servers accept connection requests on port `25.` However, newer SMTP servers also use other ports such as TCP port `587`. 

# Two disadvantages and its solution

1. The first is that sending an email using SMTP does not return a usable delivery confirmation.

2. Users are not authenticated when a connection is established, and the sender of an email is therefore unreliable. 


For this purpose, an extension for SMTP has been developed called `Extended SMTP (ESMTP).`


# ESMTP

# `When people talk about SMTP in general, they usually mean ESMTP`, ESMTP uses TLS,

************************************************************************************************************

# SMTP Service scanining

┌──(kali㉿kali)-[~]
└─$ `nmap 10.129.232.78 -p25 -sC -sV -T4`
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-03 23:45 EDT
Nmap scan report for 10.129.232.78
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp
|_smtp-commands: mail1, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
| ssl-cert: Subject: commonName=inlanefreight.htb/organizationName=Inlanefreight Ltd./stateOrProvinceName=Berlin/countryName=DE
| Not valid before: 2021-11-08T22:26:24
|_Not valid after:  2295-08-23T22:26:24
| fingerprint-strings: 
|   Hello: 
|     220 InFreight ESMTP v2.11
|_    Syntax: EHLO hostname
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port25-TCP:V=7.94SVN%I=7%D=5/3%Time=6635AF53%P=x86_64-pc-linux-gnu%r(He
SF:llo,36,"220\x20InFreight\x20ESMTP\x20v2\.11\r\n501\x20Syntax:\x20EHLO\x
SF:20hostname\r\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.72 seconds

# Connecting to SMTP Service (`telnet`)

┌──(kali㉿kali)-[~]
└─$ `telnet 10.129.232.78 25`
Trying 10.129.232.78...
Connected to 10.129.232.78.
Escape character is '^]'.
220 InFreight ESMTP v2.11

# Initialising session (`HELO` or `EHLO`)

┌──(kali㉿kali)-[~]
└─$ telnet 10.129.232.78 25
Trying 10.129.232.78...
Connected to 10.129.232.78.
Escape character is '^]'.
220 InFreight ESMTP v2.11

`HELO mail1.inlanefreight.htb`
250 mail1

`EHLO mail1`
250-mail1
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING

