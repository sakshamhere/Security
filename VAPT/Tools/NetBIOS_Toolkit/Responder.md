https://github.com/SpiderLabs/Responder


Responder an LLMNR, NBT-NS and MDNS poisoner. 

It will answer to specific NBT-NS (NetBIOS Name Service) queries based on their name suffix (see: http://support.microsoft.com/kb/163409). By default, the tool will only answer to File Server Service request, which is for SMB.

This is something which you as a pentester should run very first before any nmap scan . any nessus scans or anything at all, the reason is namap or other scan will generate their own traffic which will make traffic getting back to you