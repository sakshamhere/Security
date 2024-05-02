https://www.youtube.com/watch?v=iNdu9e6uLHM


A `PTR (Pointer) or rDNS` resord is opptosite of `A ` record

An `A` record assosiates a Domain name with IP address for example google.com --> 142.250.360.35

But just opposite a PTR (Pointer) record assossiteas an IP address with Domain name  142.250.360.35--> google.com

What is benefit of PTR recrd??

- It is typically used in context of email in a way to determine if an email server is legit

check the IP from which mail has came by SPF entry in email

use host command or dig command - to determine PTR record

    `host 209.85.220.69` 
    `69.220.85.209.in-addr.arpa` domain name pointer mail-sor-f69.google.com.

    dig -x 209.85.220.69

In response of both command we get actual PTR record `69.220.85.209.in-addr.arpa` which contains ip address in reverse with a suffix `in-addr.arpa` , this suffix is used for PTR records

So a proper way to do a PTR lookup will be 

dig -t ptr 69.220.85.209.in-addr.arpa


this will give us same output as dig -x 209.85.220.69


If the email server queries that IP for PTR address and if it dosent find it , it will consider this email as SPAM


- Typically the PTR records need to be setup by the owner of IP address

This is why its difficult to host email server at home network because our public IP is owned by ISP and they dont allow as to set up PTR records

While virtual private servers such as Linode or digitalocean allow us to do this PTR record configurations