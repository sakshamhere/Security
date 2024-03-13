# Remote Procedure Call RPC port 135

Port 135 is the RPC Endpoint Mapper service. It is a service that allows other systems to discover what services are advertised on a machine and what port to find them on.

It is a sensitive port that is associated with a slew of security vulnerabilities and should never be exposed to the internet.

However, Port 135 is needed in an active directory and server/client environment for many services to operate properly. 

You will not be able to block this port on Active Directory servers or it will break things.

# Limitations and Disadvantages 

# `Security`
There is a RPC (a RPC's Endpoint Mapper component) vulnerability in Windows NT where a malformed request to port 135 could cause denial of service (DoS). RPC contains a flaw that causes it to fail upon receipt of a request that contains a particular type of malformed data. To restore normal functionality victim has to reboot the system. Alternatively, you can upgrade/patch your OS (there is patch downloadable from Microsoft), or you can close port 135.
