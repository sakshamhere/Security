

# Types of Network 

`PAN (Personal Area Network) `	Let devices connect and communicate over the range of a person. E.g. connecting Bluetooth devices.

`LAN (Local Area Network) `	It is a privately owned network that operates within and nearby a single building like a home, office, or factory

`MAN (Metropolitan Area Network)` 	It connects and covers the whole city. E.g. TV Cable connection over the city

`WAN (Wide Area Network)` 	It spans a large geographical area, often a country or continent. The Internet is the largest WAN

`GAN (Global Area Network)` 	It is also known as the Internet which connects the globe using satellites. The Internet is also called the Network of WANs.

`VPN (Virtual Private Network)`



# Port

Ports are associated with a specific process or service and allow computers to differentiate between different traffic types (SSH traffic flows to a different port than web requests to access a website even though the access requests are sent over the same network connection).

Port numbers range from 1 to 65,535, with the range of well-known ports 1 to 1,023 being reserved for privileged services. Port 0 is a reserved port in TCP/IP networking and is not used in TCP or UDP messages. If anything attempts to bind to port 0 (such as a service), it will bind to the next available port above port 1,024 because port 0 is treated as a "wild card" port.

There are two categories of ports, Transmission Control Protocol (TCP), and User Datagram Protocol (UDP).

Some of the most well-known TCP and UDP ports are listed below:

Port(s) 	Protocol
20/21 (TCP) 	FTP
22 (TCP) 	SSH
23 (TCP) 	Telnet
25 (TCP) 	SMTP
80 (TCP) 	HTTP
161 (TCP/UDP) 	SNMP
389 (TCP/UDP) 	LDAP
443 (TCP) 	SSL/TLS (HTTPS)
445 (TCP) 	SMB
3389 (TCP) 	RDP

ports and references
https://packetlife.net/media/library/23/common-ports.pdf
https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/

# Shell

Shell is a very common term that we will hear again and again during our journey. It has a few meanings. On a Linux system, the shell is a program that takes input from the user via the keyboard and passes these commands to the operating system to perform a specific function. In the early days of computing, the shell was the only interface available for interacting with systems. Since then, many more operating system types and versions have emerged along with the graphic user interface (GUI) to complement command-line interfaces (shell), such as the Linux terminal, Windows command-line (cmd.exe), and Windows PowerShell.

There are three main types of shell connections:

1. Reverse shell 	Initiates a connection back to a "listener" on our attack box.

2. Bind shell 	    "Binds" to a specific port on the target host and waits for a connection from our attack box.

3. Web shell 	    Runs operating system commands via the web browser, typically not interactive or semi-interactive. It can also be used to run single 
                    commands (i.e., leveraging a file upload vulnerability and uploading a PHP script to run a single command.


# Tools such as SSH, Netcat, Tmux, and Vim are essential and are used daily by most information security professionals. Although these tools are not intended to be penetration testing tools, they are critical to the penetration testing process, so we must master them.

# Using SSH

Secure Shell (SSH) is a network protocol that runs on port 22 by default and provides users such as system administrators a secure way to access a computer remotely. SSH can be used to remotely access systems on the same network, over the internet, facilitate connections to resources in other networks using port forwarding/proxying, and upload/download files to and from remote systems.


SSH can be configured with password authentication or passwordless using public-key authentication using an SSH public/private key pair. SSH uses a client-server model, connecting a user running an SSH client application such as OpenSSH to an SSH server.

An SSH connection is typically much more stable than a reverse shell connection and can often be used as a "jump host" to enumerate and attack other hosts in the network, transfer tools, set up persistence, etc. 

If we obtain a set of credentials, we can use SSH to login remotely to the server by using the username @ the remote server IP, as follows:

Doshi@htb[/htb]$ ssh Bob@10.10.10.10

Bob@remotehost's password: *********

Bob@remotehost#

# Using Netcat

Netcat, ncat, or nc, is an excellent network utility for interacting with TCP/UDP ports. It can be used for many things during a pentest. Its primary usage is for connecting to shells,

In addition to that, netcat can be used to connect to any listening port and interact with the service running on that port. 

For example, SSH is programmed to handle connections over port 22 to send all data and keys. We can connect to TCP port 22 with netcat:

Doshi@htb[/htb]$ netcat 10.10.10.10 22

SSH-2.0-OpenSSH_8.4p1 Debian-3

* Banner Grabbing

As we can see, port 22 sent us its banner, stating that SSH is running on it. This technique is called Banner Grabbing, and can help identify what service is running on a particular port.

N