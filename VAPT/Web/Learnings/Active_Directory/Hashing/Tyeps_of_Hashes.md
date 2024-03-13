
list - https://hashcat.net/wiki/doku.php?id=example_hashes

0 	MD5 	8743b52063cd84097a65d1633f5c74f5
10 	md5($pass.$salt) 	01dfae6e5d4d90d9892622325959afbe:7050461
20 	md5($salt.$pass) 	f0fda58630310a6dd91a7d8f0a4ceda2:4225637426
30 	md5(utf16le($pass).$salt) 	b31d032cfdcf47a399990a71e43c5d2a:144816
40 	md5($salt.utf16le($pass)) 	d63d0e21fdc05f618d55ef306c54af82:13288442151473
50 	HM