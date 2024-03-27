https://fallbackstatus.com/how-does-active-directory-communicate/

# How does Active Directory communicate?

Active Directory (AD) relies on several communications services to communicate with client computers and between domain controllers.

Basic Communications

AD needs only a few basic services to be available for normal operations:

`TCP port 139 and UDP port 138` are needed for file replication between domain controllers. This port combination is the standard `NetBIOS `session service port set.

`UDP port 389 handles LDAP queries` and is used for normal domain controller operations.

`TCP port 636` is for `LDAP over Secure Sockets Layer (SSL)`, which is the default LDAP methodology for Windows Server 2003 and later.

`TCP and UDP ports 445 `are used for file replication and are the standard Windows file sharing ports ie `SMB`.

`TCP and UDP ports 53` are used to communicate with `Domain Name System (DNS)`, which is a vital part of AD communications. 

`TCP and UDP ports 464` are the `Kerberos password change` protocol ports.

`User Datagram Protocol (UDP) port 88` is used for `Kerberos authentication`. Transmission Control Protocol (TCP) port 88 can also be used, although it's less common.

`TCP port 593 `is used by the `RPC over HTTP transport`. Although you don't technically need this port for normal operations, I'll discuss later how this feature can make working with domain controllers through firewalls a bit easier.


# Generally, opening these ports between clients and domain controllers, or between domain controllers, will enable AD to function normally. `One exception is RPC traffic. `

`TCP and UDP ports 135` are needed for `remote procedure call (RPC)` endpoint mapping. RPCs are used for a number of domain controller-to-domain controller and client-todomain controller operations. Unfortunately, not all communications take place over port 135, as I'll discuss later.

`TCP port 593 `is used by the `RPC over HTTP transport`. Although you don't technically need this port for normal operations, I'll discuss later how this feature can make working with domain controllers through firewalls a bit easier.