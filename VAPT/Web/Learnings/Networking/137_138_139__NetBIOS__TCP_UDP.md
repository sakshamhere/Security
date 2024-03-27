# Network Basic Input/Output System

https://wirexsystems.com/resource/protocols/netbios/, https://www.lifewire.com/netbios-software-protocol-818229
https://www.youtube.com/watch?v=Qn-2XQ-0wLg

NetBIOS, an abbreviation for `Network Basic Input/Output System`, is a networking industry standard.

Netbios is a `legacy network protocol` that enables communication between computers and devices `within a local area network (LAN)`.

Netbios was widely used earlier for sharing files, printers, and other resource access on a LAN.

NETBIOS typically runs over transport protocols such as TCP/IP, using protocols like NBT (NetBIOS over TCP/IP) to transmit data packets. 

# However, in modern network environments, `NETBIOS has been largely replaced` by more advanced and secure technologies, `such as DNS (Domain Name System) for name resolution and SMB (Server Message Block) for file and printer sharing`. Additionally, the widespread adoption of Active Directory in Windows-based networks has diminished the need for NETBIOS. Despite its decline in use, some legacy systems and applications may still rely on NETBIOS for communication and resource sharing `within LANs.`

# Windows today uses `NBT` (NetBIOS over TCP/IP) to communicate to other devices


*******************************************************************************************************************************************
# What is Netbios and its Use -

NETBIOS is an application programming interface (API) that operates at the session layer (Layer 5) of the OSI (Open Systems Interconnection) model. It provides services, such as `name service, datagram service, and session service`, to facilitate communication between devices on a network.

`Name service (NetBIOS-NS):` This service is responsible for registering, releasing, and resolving computer names to their IP addresses, enabling communication between devices on the network `Over UDP on port 137`.

`Datagram service (NetBIOS-DGM):` It provides a connectionless communication method for sending messages or data packets between devices in a LAN without establishing a dedicated connection. `Over UDP on port 138`

`Session service (NetBIOS-SSN):` This service facilitates connection-oriented communication between devices in a LAN, allowing the exchange of data through established sessions. `Over TCP on port 139`


- In Windows, the NetBIOS name is separate from the computer name and can be up to 16 characters long. 

- Software applications on a NetBIOS network locate and identify each other through their NetBIOS names.

- Applications on other computers access NetBIOS names over `UDP on port 137. `

- Two applications start a NetBIOS session when the client sends a command to "call" another client (the server) over `TCP on port 139.` This is referred to as the session mode, where both sides issue "send" and "receive" commands to deliver messages in both directions. The "hang-up" command terminates a NetBIOS session.

- NetBIOS also supports connectionless communications through UDP. Applications listen `on UDP port 138` to receive NetBIOS datagrams. The datagram service sends and receives datagrams and broadcasts datagrams.



# Options for `Netbios Name Service` on port 137

`Find name` is for looking up a NetBIOS name on the network
`Add name` to register the NetBIOS name
`Add group name `is similar but registers the NetBIOS group name
`Delete name `is for unregistering a NetBIOS name, whether it be a name or group

# Options for `Netbios Datagram mode` on port 138

`Send Datagram` will send a datagram through0. the NetBIOS name
`Send Broadcast Datagram` is for sending a datagram to every registered NetBIOS name on the network
`Receive Datagram` waits for a Send Datagram packet
`Receive Broadcast Datagram` waits for a Send Broadcast packet
    
# Options for `Netbios Session mode` on port 139

`Call `to start a session through the NetBIOS name
`Listen `will see if an attempt can be made to open the session
`Hang` Up is used to close a session
`Send` will send a packet over the session
`Send No Ack` is the same as send but doesn't require an acknowledgment that it was sent through the session
`Receive `waits for the incoming packet



# Netbios Suffix Code
http://www.pyeung.com/pages/microsoft/winnt/netbioscodes.html

Example - 20 is for File server serice, that means SMBclient can be used to connect

**********************************************************************************************************************************

# Netbios Limitations & Disadvantages

# `Security:` 
NETBIOS lacks built-in security features, making it vulnerable to various attacks, such as spoofing, man-in-the-middle attacks, and unauthorized access to network resources. Modern protocols like SMB and Active Directory offer improved security measures to protect data and network resources.

# `Scalability: `
NETBIOS was designed for small local area networks (LANs) and does not scale well to larger networks. As the number of devices and resources in a network grows, NETBIOS becomes less efficient, leading to increased network traffic and slower performance.

# `Limited Routing Capabilities:` 
NETBIOS is not a routable protocol by itself, which means it is limited to communication within a single LAN. To work across different networks or over the internet, it requires encapsulation within a transport protocol like TCP/IP (using NBT, or NetBIOS over TCP/IP).

# `Reliance on Broadcasts: `
NETBIOS relies heavily on broadcast messages for functions like name resolution and communication, which can lead to increased network congestion and decreased performance, especially in larger networks.

# `Obsolescence:` 
As more `advanced technologies like DNS for name resolution and SMB for file and printer sharing have been developed and adopted`, NETBIOS has become increasingly obsolete. These newer protocols offer better performance, security, and features, making them the preferred choice for modern network environments.
