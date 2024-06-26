
# Internet Message Access Protocol (IMAP)

With the help of the Internet Message Access Protocol (IMAP), access to emails from a mail server is possible. 

`SMTP` is usually used to send emails. By copying sent emails into an `IMAP` folder, all clients have access to all sent mails, regardless of the computer from which they were sent. 

Another advantage of the Internet Message Access Protocol is creating personal folders and folder structures in the mailbox. This feature makes the mailbox clearer and easier to manage.

IMAP allows online management of emails directly on the server and supports folder structures. `Thus, it is a network protocol for the online management of emails on a remote server. `

The protocol is client-server-based and allows synchronization of a local email client with the mailbox on the server, providing a kind of network file system for emails, allowing problem-free synchronization across several independent clients.

Emails remain on the server until they are deleted. IMAP is text-based and has extended functions, such as browsing emails directly on the server. It is also possible for several users to access the email server simultaneously. 

# Client Connecting IMAP

The client establishes the connection to the server via port `143`. For communication, it uses text-based commands in ASCII format. Several commands can be sent in succession without waiting for confirmation from the server. Later confirmations from the server can be assigned to the individual commands using the identifiers sent along with the commands. Immediately after the connection is established, the user is authenticated by `user name and password` to the server. Access to the desired mailbox is only possible after successful authentication.

IMAP works `unencrypted` and transmits commands, emails, or usernames and passwords in plain text. Many email servers require establishing an encrypted IMAP session, the `encrypted connection uses the standard port 143 or an alternative port such as 993.`