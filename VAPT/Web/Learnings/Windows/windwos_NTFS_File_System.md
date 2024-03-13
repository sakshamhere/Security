
# File System used in older windows versions

# `FAT (File Allocation Table)`

You still see FAT partitions in use today. For example, you typically see FAT partitions in USB devices, MicroSD cards, etc. but traditionally not on personal Windows computers/laptops or Windows servers.

# File System used in modern windows verions

# `NTFS (New Technology File System)`

NTFS is known as a journaling file system. In case of a failure, the file system can automatically repair the folders/files on disk using information stored in a log file. This function is not possible with FAT.   

NTFS addresses many of the limitations of the previous file systems; such as: 

    Supports files larger than 4GB
    Set specific permissions on folders and files
    Folder and file compression
    Encryption (Encryption File System or EFS)

`Alternate Data Streams (ADS) `is a file attribute specific to Windows NTFS (New Technology File System).

Every file has at least one data stream ($DATA), and ADS allows files to contain more than one stream of data. Natively Window Explorer doesn't display ADS to the user. There are 3rd party executables that can be used to view this data, but Powershell gives you the ability to view ADS for files