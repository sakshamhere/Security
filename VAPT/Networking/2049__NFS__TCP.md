
# Network File System

`NFS` has same purpose as `SMB` ie accessing files.

`Server Message Block (SMB)` and `Network File System (NFS)` protocols both operate with a client-server model, where files are shared on the remote server and used by the local client. Once the protocols are set up correctly, when you access remote network files and directories on the server, it works as if they were local to the file system on the client machine.

# What is diffrence?

The SMB protocol was designed specifically for Windows systems.

While NFS protocol was designed specifically for Unix systems.


SMB has been built so you can share a wide range of network resources, including file and print services, storage devices, and virtual machine storage.

This is in contrast to NFS, which only has built-in support for sharing files and directories.

# Default Configuration

NFS is not difficult to configure because there are not as many options as FTP or SMB have. 

The `/etc/exports` file contains a table of physical filesystems on an NFS server accessible by the clients. 

# Dangerous settings

`rw` 	                Read and write permissions.
`insecure `	        Ports above 1024 will be used.
`nohide `	        If another file system was mounted below an exported directory, this directory is exported by its own exports entry.
`no_root_squash` 	    All files created by root are kept with the UID/GID 0.


If the `“no_root_squash”` option is present on a writable share, we can create an executable with SUID bit set and run it on the target system.

`insecure` option. This is dangerous because users can use ports above 1024. The first 1024 ports can only be used by root. This prevents the fact that no users can use sockets above port 1024 for the NFS service and interact with it.

# Common commands

1. Show Available NFS Shares

Doshi@htb[/htb]$ `showmount -e 10.129.14.128`

Export list for 10.129.14.128:
/mnt/nfs 10.129.14.0/24


2. Mounting NFS Share

Doshi@htb[/htb]$ `mkdir target-NFS`
Doshi@htb[/htb]$ `sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock`
Doshi@htb[/htb]$ `cd target-NFS`
Doshi@htb[/htb]$ `tree .`

.
└── mnt
    └── nfs
        ├── id_rsa
        ├── id_rsa.pub
        └── nfs.share

2 directories, 3 files


3. Unmounting

Doshi@htb[/htb]$ `sudo umount ./target-NFS`