https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp
http://motasem-notes.net/understanding-and-pentesting-smtp-mail-servers-tryhackme-smtp-network-services-2/

The `Simple Mail Transfer Protocol (SMTP)` is a protocol utilized within the TCP/IP suite for the sending and receiving of e-mail. 

Due to its limitations in queuing messages at the recipient's end, SMTP is often employed alongside either `POP3 or IMAP`. These additional protocols enable users to store messages on a server mailbox and to periodically download them.

In practice, it is common for e-mail programs to employ `SMTP for sending e-mails`, while utilizing `POP3 or IMAP for receiving them`

Default port: 25,465(ssl),587(ssl)

A SMTP-server is capable of acting as a client and a server, as it needs to send and receive emails at the same time.
The SMTP server performs three basic functions:

     It verifies who is sending emails through the SMTP server.
     It sends the outgoing mail
     If the outgoing mail can’t be delivered it sends the message back to the sender


# SMTP role on SMTP server
when you configure a new email client, you will need to configure the SMTP server configuration in order to send outgoing emails.
The role of the SMTP server in this service, is to act as the sorting office, the email (letter) is picked up and sent to this server, which then directs it to the recipient.

# POP and IMAP role on SMTP server
`POP`, or `“Post Office Protocol”` and `IMAP`, `“Internet Message Access Protocol”` are both email protocols who are responsible for the transfer of email between a client and a mail server. The main differences is in `POP’s` more simplistic approach of downloading the inbox from the mail server, to the client. Where `IMAP` will synchronise the current inbox, with new mail on the server, downloading anything new. 


# A Mail Flow
A workflow of an email´s travel from one user to another could look like so:

MUA -> MSA -> MTA -> internet -> MTA -> MDA -> MUA

`Mail User Agent (MUA)`: This is a (part of a) program connecting to a SMTP-server in order to send an email. Most likely this is your Outlook, Thunderbird, whatever.

`Mail Transfer Agent (MTA)`: The transport service part of a program. They receive and transfer the emails. This might be an Exchange server, an internet facing gateway and so on.

The mail-flow will look like:

Outlook -> Exchange -> firewall -> internet -> SMTP-Server of the receiving side -> mail-server of the receiving side -> Outlook of receiver


# Attacking SMTP-Servers