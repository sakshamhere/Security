https://www.samba.org/samba/docs/current/man-html/nmblookup.1.html

# nmblookup — NetBIOS over TCP/IP client used to lookup NetBIOS names

nmblookup is used to query NetBIOS names and map them to IP addresses in a network using NetBIOS over TCP/IP queries.

The options allow the name queries to be directed at a particular IP broadcast area or to a particular machine. 

All queries are done over UDP.


Flags

-A|--lookup-by-ip

    Interpret name as an IP Address and do a node status query on this address.