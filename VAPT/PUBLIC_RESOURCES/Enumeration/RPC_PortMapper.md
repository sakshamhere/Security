https://book.hacktricks.xyz/network-services-pentesting/pentesting-rpcbind

# RPC Portmapper

Similar to MSRPC (Endpoint Mapper) in `Windows-based systems`, RPC Portmapper acts as a critical component in `Unix-based systems`, facilitating the exchange of information between these systems.

The `port 111` associated with Portmapper is frequently scanned by attackers as it can reveal valuable information. 

This information includes the type of Unix Operating System (OS) running and details about the services that are available on the system. 

Additionally, Portmapper is commonly used in conjunction with `NFS (Network File System)`, `NIS (Network Information Service)`, and other `RPC-based service`s to manage network services effectively.