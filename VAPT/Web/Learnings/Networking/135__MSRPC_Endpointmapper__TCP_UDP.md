https://superuser.com/questions/1429579/usefulness-of-having-port-135-open-in-active-directory-environment

# Microsoft RPC Remote Control Protocol (RPC Locat)

TCP port 135 is the `MSRPC` endpoint mapper. 

`It is a service that allows other systems to discover what services are advertised on a machine and what port to find them on. It is mostly associated with remote access and remote management.`

The RPC endpoint mapper allows RPC clients to determine the port number currently assigned to a particular RPC service. An endpoint is a protocol port or named pipe on which the server application listens to for client remote procedure calls.

The RPC endpoint mapper can be accessed via TCP and UDP port 135.

It is a service that allows other systems to discover what services are advertised on a machine and what port to find them on.

So, as an admin responsible for managing those devices "remotely," you may want to leave the port open but restrict access to it on the windows firewall to only your local IP addresses for security purposes.


If you would like to see what services depend on Port 135 you can review this document: https://support.microsoft.com/en-us/help/832017/service-overview-and-network-port-requirements-for-windows



# Where used

However, Port 135 is needed in an active directory and server/client environment for many services to operate properly. 

You will not be able to block this port on Active Directory servers or it will break things.

# Security risk

It is a sensitive port that is associated with a slew of security vulnerabilities and should never be exposed to the internet.

Just like a door in your home, if left open, can potentially let anyone in, so can TCP port 135.

This poses a problem with a TCP port 135 vulnerability that can theoretically enable hackers or unauthorized users to access a computer system. If the port is left open, strong authentication measures need to be implemented on a given system to limit access to services by unauthorized users. Extreme caution needs to be taken when opening port 135 to ensure a system’s security.

***********************************************************************************************************************************************************


