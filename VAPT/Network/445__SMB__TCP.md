SMB

The SMB uses`TCP port 445` However Orignially SMB ran on top of `NetBIOS` using `TCP Port 139`.

SMB requires different network ports on a machine to enable communications with other systems. SMB originally ran on top of NetBIOS, which uses port 139. NetBIOS is an older transport layer which allows computers to talk to each other on the network. The SMB protocol runs on port 445, but may rely on NetBIOS to communicate with old devices that do not support the direct hosting of SMB over TCP/IP.

SMB is used to share files, and other things by network drive/shares, also this is how printer is able to print from diffrent machines

SMB (Server Message Block) is a prevalent protocol on Windows machines that provides many vectors for vertical and lateral movement. 

Sensitive data, including credentials, can be in network file shares, and some SMB versions may be vulnerable to RCE exploits such as EternalBlue. 

It is crucial to enumerate this sizeable potential attack surface carefully. Nmap has many scripts for enumerating SMB, such as smb-os-discovery.nse, which will interact with the SMB service to extract the reported operating system version.

`SAMBA` is open source Linux Implementation of SMB and allows windows system to access linux shares.

# SMB Authentication

SMB Protocol utilizes two levels of authentication

1. User Authentication

2. Share Authentication


User Authentication  - User must provide username and password in order to authenticate to SMB server in order to access the share.

Share Authentication - Usetr musst provide a password in order to access restricted share.

# Importance of SMB in context of `Active Directory`

Here are some key reasons why SMB is important in the context of Active Directory:

`File Sharing:` SMB allows users to access shared folders and files on networked computers. In an Active Directory environment, administrators can easily manage and control access to shared resources, ensuring that only authorized users or groups have the necessary permissions to access specific files or directories.

`User Authentication:` When users access shared resources on a network, SMB facilitates the authentication process with the Active Directory domain controllers. This means that users must provide valid credentials (username and password) to access shared resources, ensuring security and accountability.

`Group Policy: `Active Directory relies on Group Policy Objects (GPOs) to manage the configuration of user and computer settings within the network. SMB plays a role in deploying these GPOs to domain-joined computers, allowing administrators to enforce security policies, software installations, and various configurations on a large scale.

`Distributed File System (DFS):` SMB is also used for Distributed File System, which allows administrators to create a logical view of shared folders and files from multiple servers. This enhances the fault tolerance and availability of data by replicating files across different servers.

`Roaming Profiles:` SMB is involved in supporting roaming profiles in Active Directory environments. Roaming profiles enable users to have a consistent desktop experience across multiple computers as their settings and files are synchronized from one computer to another.

`Printer Sharing:` SMB is utilized for printer sharing in an Active Directory environment. This allows network users to discover and connect to shared printers, simplifying the process of deploying and managing printers throughout the network.

`Integration with Other Services:` Active Directory is a core component of the Windows ecosystem, and many other services and applications within the Windows environment rely on SMB for communication and resource sharing. This includes services like Windows File Sharing, Remote Procedure Call (RPC) over SMB, and various management and administrative tools.

# SMB Authentication Process with `Active Directory Domain Controllers

SMB facilitates the authentication process with Active Directory domain controllers through a mechanism known as the `NT LAN Manager (NTLM) protocol` and `Kerberos authentication.` Both methods involve different approaches to validate the identity of users and establish a secure connection between clients and domain controllers.`