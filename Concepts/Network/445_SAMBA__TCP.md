https://www.redhat.com/sysadmin/getting-started-samba
https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/4/html/reference_guide/ch-samba#samba-overview
https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/4/html/reference_guide/s1-samba-daemons


# `SAMBA` is open source Linux Implementation of SMB and allows windows system to access linux shares.

So for example we have many windows system then obviously we can use SMB file share service to share files with each other, however what if we have some linux servers also, this is where `SAMBA` helps us to access linux shares as well from windows system

SAMBA is linux implementation of SMB, and allows windows system to access linux shares and devices.

SAMBA dosent comes with linux by default like SMB i windows, but instead we need to install it.

`SAMBA` is not so common service that you find running on linux server, but its something we may find on an internal network.

`SAMBA` utilizes username and password authentication just like SMB to get access to server or network share.


# `SMBmap` - A kali linux tool
We can brute force to obtain credentials. and once we get them we can use `SMBmap` to enumerate SAMBA share, list contents, upload and ownload files.

# `smbclient` - A part of SAMBA suite

we can utilize `smbvlclient` it communicates with LAN Manager server offering an interface similar to that of `FTP`.

It can be used to upload,download and retrive dictionary information from SAMBA server.



Originally, Samba was developed in 1991 for fast and secure file and print share for all clients using the SMB protocol. 

Samba is comprised of three daemons `smbd`, `nmbd`, and `winbindd`

# `smbd`

The `smbd `server daemon provides file sharing and printing services to Windows clients. 

In addition, it is responsible for user authentication, resource locking, and data sharing through the SMB protocol. 

The default ports on which the server listens for SMB traffic are `TCP ports 139 and 445.` 

The smbd daemon is controlled by the smb service. 

# `nmbd`

The `nmbd `server daemon understands and replies to NetBIOS name service requests such as those produced by SMB/CIFS in Windows-based systems.

The default port that the server listens to for NMB traffic is `UDP port 137. `