
Host file is something which is present in both linux and windows machine,  this contains host name and the ip address which it resolved to.

This is sort of our local DNS server , we can specify a ip and map it to IP which we want to resolve.

for linux


└─$ cat /etc/hosts     
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters


we can add our router 192.168(jiofiber) address in it to resolve direclty

─$ sudo vim /etc/hosts

└─$ cat /etc/hosts     
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
192.168.29.1    myrouter
