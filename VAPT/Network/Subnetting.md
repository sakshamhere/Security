https://www.youtube.com/watch?v=HU-tOXwJsmc

https://docs.google.com/spreadsheets/d/1IfcJbz90sAZMQ7lx1La6lRN91hHWsybB/edit#gid=557026227

┌──(kali㉿kali)-[~]
└─$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.204.130  netmask 255.255.255.0  broadcast 192.168.204.255
        inet6 fe80::9d5c:a00d:b7e2:bfdf  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:0d:4f:91  txqueuelen 1000  (Ethernet)
        RX packets 369277  bytes 265894558 (253.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 329369  bytes 52347596 (49.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 396  bytes 36219 (35.3 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 396  bytes 36219 (35.3 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

******************************************

`netmask 255.255.255.0 `

We have this netmask which is also called `Subnet`

There are two ways to show Subnetting

One is `Decimal Notation of Subnet Mask` - 255.255.255.0

Another is `CIDR Notation` - 192.168.1.0/24

Both of these are very common

The Decimal Notation can also be translated into `Binary Notation`

        255.255.255.0

1111111.1111111.1111111.00000000

######################################################################################################################

                            255           .                 255             .                255             .                255

            1   1   1   1   1   1   1   1     1   1   1   1   1   1   1   1     1   1   1   1   1   1   1   1     1   1   1   1   1   1   1   1

            128 64  32  16  8   4   2   1     128 64  32  16  8   4   2   1     128 64  32  16  8   4   2   1     128 64  32  16  8   4   2   1


Total=      255                               255                               255                                255



Note - Once a Zero occours a One cannot occour after that

######################################################################################################################

So Now what will this be?

                            255           .                 255             .                255             .                255

            1   1   1   1   1   1   1   1     1   1   1   1   1   1   1   1     1   1   1   0   0   0   0   0     0   0   0   0   0   0   0   0

            128 64  32  16  8   4   2   1     128 64  32  16  8   4   2   1     128 64  32  16  8   4   2   1     128 64  32  16  8   4   2   1


Total=      255                               255                               224                                0



So for `Subnet` do total for all the 1 bits that will be `255.255.224.0`

And for `Subnet Mask` calculate the one's in this case it is  - `19`

So the Complete CIDR Notation will be  - `255.255.224.0/19`


******************************************************************************************

# Finding number of Host available and subnet


https://docs.google.com/spreadsheets/d/1IfcJbz90sAZMQ7lx1La6lRN91hHWsybB/edit#gid=557026227

                                                        Subnet x.0.0.0							

CIDR	  /1	              /2	              /3	          /4	          /5	          /6	          /7	          /8
Hosts	  2,147,483,648 	  1,073,741,824 	  536,870,912 	  268,435,456 	  134,217,728 	  67,108,864 	  33,554,432 	  16,777,216 
	
                                                        Subnet 255.x.0.0							

CIDR	  /9	              /10	              /11	          /12	          /13	          /14	          /15	          /16
Hosts	  8,388,608 	      4,194,304 	      2,097,152 	  1,048,576 	  524,288 	      262,144 	      131,072 	      65,536 
	
                                                        Subnet 255.255.x.0							

CIDR	  /17	              /18	              /19	          /20	          /21	          /22	          /23	          /24
Hosts	  32,768 	          16,384 	          8,192 	      4,096 	      2,048 	      1,024 	      512 	          256 
	
                                                        Subnet 255.255.255.x							 

CIDR	  /25	              /26	              /27	          /28	          /29	          /30	          /31	          /32
Hosts	  128 	              64 	              32 	          16 	          8 	           4 	           2 	           1 



Subnet    128	              192	              224	          240	           248	          252	          254	           255
Mask 


# NOTE

- Number of Host doubles when subnet mask increases by 1

- Always subtract 2 host (reserved for Network and Broadcast ID) after calculating host from 2^(number of OFF bits) for total hosts

    Netowork ID - your network id is typically your First address
    Broadcast ID - your broadcast id is typically your Last address

    If we see we can see network id as `netmask 255.255.255.0` and broadcast id as `broadcast 192.168.204.255`

    eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
            inet 192.168.204.130  `netmask 255.255.255.0`  `broadcast 192.168.204.255`
            inet6 fe80::9d5c:a00d:b7e2:bfdf  prefixlen 64  scopeid 0x20<link>
            ether 00:0c:29:0d:4f:91  txqueuelen 1000  (Ethernet)
            RX packets 369277  bytes 265894558 (253.5 MiB)
            RX errors 0  dropped 0  overruns 0  frame 0
            TX packets 329369  bytes 52347596 (49.9 MiB)
            TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0



- The /24 and /16 are very common in use

 - /24 for places where less number of host like home network

 - while big organisation which require huge number of hosts use /16 and may use /8


# Example 
 So considerwe have CIDR Notation  `192.168.1.0/24` 

this is /24 mask means 255.255.255.0

which means there are 24 ON bits and 8 OFF bits

Let the Host be X

So the number of host available will be 

X = 256 

Once we know X we need to substract 2 for the Broadcast Id and Network Id which are reserved

So the actual number of host available in this subnet will be

X = 254

Which means we can 254 host in a /24 network


# Question

Provide below details for 192.168.1.0/24, 192.168.1.0/28, 192.168.1.16/28

1. Subnet 
2. No of Hosts
3. Network Id
4. Broadcast id

# Answer

                    Subnet              Hosts           Network         Broadcast

192.168.1.0/24   255.255.255.0          254            192.168.1.0      192.168.1.255
192.168.1.0/28   255.255.255.240        14             192.168.1.0      192.168.1.15
192.168.1.16/28  255.255.255.240        14             192.168.1.16     192.168.1.31
192.168.0.0/23   255.255.254.0          510            192.168.0.0      192.168.1.255
192.168.1.0/23   255.255.254.0          510            192.168.1.0      192.168.2.255
192.168.2.0/23   192.168.254.0          510            192.168.2.0      192.168.3.255

Similar calculation can be done using online calculator - https://www.ipaddressguide.com/cidr

Some more example

                    Subnet              Hosts           Network         Broadcast

192.168.0.0/22   192.168.252.0          1022          192.168.0.0      192.168.3.255

Noe here what i noticed that just do approx calculation in mind by deviding 1000 by 250 youw will think of 4 iteration and so 3.255 is end


192.168.1.0/26   255.255.255.192         62               192.168.1.0    192.168.1.64
