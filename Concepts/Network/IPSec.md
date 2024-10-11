
https://www.tutorialspoint.com/network_security/network_security_layer.htm


Security protocols have evolved for network security ensuring security such as privacy, authentication, message integrity and non-repudiation.

Most of these protocols remained focused on the higher level of OSI, for example SSL was developed to secure appplications using HTTP, FTP etc. but there are other applications also which needs to be secured, this gave rise to develop a security solution at IP layer or network layer so that all protols at higher OSI levels can take advantage of it and be secure.

In 1992, the Internet Engineering Task Force (IETF) began to define a standard `‘IPsec’.`

IPsec is a suite of protocols for securing network connections. It is rather a complex mechanism, because instead of giving straightforward definition of a specific encryption algorithm and authentication function, it provides a framework that allows an implementation of anything that both communicating ends agree upon.

`Transport Mode` provides a secure connection between two endpoints without changing the IP header. `Tunnel Mode` encapsulates the entire payload IP packet. It adds new IP header. The latter is used to form a traditional VPN, as it provides a virtual secure tunnel across an untrusted Internet.

`Authentication Header (AH)` and `Encapsulating Security Payload (ESP)` are the two main communication protocols used by IPsec. While AH only authenticate, ESP can encrypt and authenticate the data transmitted over the connection.

Setting up an IPsec connection involves all kinds of crypto choices. Authentication is usually built on top of a cryptographic hash such as MD5 or SHA-1. Encryption algorithms are DES, 3DES, Blowfish, and AES being common. Other algorithms are possible too.

Both communicating endpoints need to know the secret values used in hashing or encryption. Manual keys require manual entry of the secret values on both ends, presumably conveyed by some out-of-band mechanism, and `IKE (Internet Key Exchange)` is a sophisticated mechanism for doing this online.

********************************************************************************************************
# Features

- IPsec protects the entire packet in network layer including higher OSI layer headers.

- Confidentiality 
    - Enables encryption and Prevents eavesdropping by third parties.

- Integrity
    - Provides assurance that a received packet was actually transmitted by the party identified as the source in the packet header.
    - Confirms that the packet has not been altered or otherwise.

# Use

- `The most common use of IPsec is to provide a Virtual Private Network `(VPN)`,` either between two locations (gateway-to-gateway)/(site-to-site) or between a remote user and an enterprise network (host-to-gateway)(point-to-site).


# Internet Key Exchange `(IKE)`

- IKE is the automatic key management protocol used for IPsec.

- Technically, key management is not essential for IPsec communication and the keys can be manually managed. However, manual key management is not desirable for large networks.

- `IKE is responsible for creation of keys for IPsec and providing authentication during key establishment process`.

- Though, IPsec can be used with other key management protocols, IKE is used by default.


# IPsec Communication Modes

1. `Transport Mode`
2. `Tunnel Mode`


`Transport Mode`

- IPsec does not encapsulate a packet received from upper layer.

- The original IP header is maintained and the data is forwarded based on the original attributes set by the upper layer protocol.



        System with IPSec -------Router    ---------  Router  ----------System with IPSec     



`Tunnel Mode`

- This mode of IPsec provides encapsulation services along with other security services.

- In tunnel mode operations, the entire packet from upper layer is encapsulated before applying security protocol and New IP header is added.

- The datagram from one system forwarded to the gateway is encapsulated and then forwarded to the remote gateway. The remote associated gateway de-encapsulates the data and forwards it to the destination endpoint on the internal network.


        System  -------IPsec aware Router   ---------  IPsec aware Router ----------System  




- Using IPsec, the tunneling mode can be established between the gateway and individual end system as well.


        System with IPSec ------- Router   ---------  IPsec aware Router ----------System  



# IPsec Protocols

IPsec uses the security protocols to provide desired security services. These protocols are the heart of IPsec operations and everything else is designed to support these protocol in IPsec.

There are two security protocols defined by IPsec — `Authentication Header (AH)` and `Encapsulating Security Payload (ESP).`


Authentication Header (AH) and Encapsulating Security Payload (ESP) are the two main communication protocols used by IPsec. While AH only authenticate, ESP can encrypt and authenticate the data transmitted over the connection.