https://www.computernetworkingnotes.com/linux-tutorials/the-etc-hosts-etc-resolv-conf-and-etc-nsswitch-conf-files.html

# /etc/hosts                        

# /etc/resolve.conf                 

# /etc/nsswitch.conf

******************************************************************************************************************8

# /etc/hosts

All operating systems include a file called `hosts`.

This file basically acts as DNS Server but for local network, for example we have a website and webserver on our machine, we can access with any domain name for example attacker.com,  for this we map this name with the IP of our server. 

Every time you access a network resource, the operating system checks this file to figure out the corresponding IP address.

OS first checks the `/etc/hosts` file to know the associated IP address. If it doesn't find an entry for the name, it uses the DNS server to know the IP address associated with the name.

A DNS server does the same task on the network that the /etc/hosts file does on the local system

# /etc/resolve.conf

Just like /etc/host acts as DNS server for local system,  `/etc/resolve.conf` acts as DNS server for Network of systems.

Linux uses the `/etc/resolv.conf` file to `stores the DNS server's IP address`. It updates this file from network connections.

Linux uses the `/etc/resolv.conf `file to forward the unresolved query to the DNS server IP addresses mentioned in it. The DNS server resolves the query and sends the solved query back to the Linux system.

When you configure the DNS server's IP address in a connection, NetworkManager automatically updates the DNS server's IP address in the `/etc/resolv.conf` file from the connection.


# /etc/nsswitch.conf

The order in which the `/etc/hosts` and `/etc/resolv.conf` files are checked is defined in the `/etc/nsswitch.conf` file.

This file also defines the default search order for many other services such as hostname, users, groups, passwords, etc.