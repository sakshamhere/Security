
# Bind Shells

A Bind shll is a type of remote shell where attacker connects directly to a listener on the target system, consequently allowing for execution of commands on the target system.

In order to get a bind shell on remote system a netcat listener can be set up on remote system 

This netcat listener should be configured to execute cmd.ex / powesershell.exe in case of windows and is linux then the default bourne shell ie /bin/sh or bash shell /bin/bash any other shell like z shell etc

# Reverse Shells

In this the context is just opposite to Bind shell, in this the remote system connects to our attacker system which acts as a listener

# `Reverse Shells are much Better than Bind shells !!!` - Why?

In case of Bind shell

- We need to setup a netcat listerner on target - Practically how do we even do it if dont have access to the target system

- In almost all systems the inbound traffic will be blocked by firewall ro soem other network security


# In which case `Bind Shell` are better

Bind shells are most likely to be used in an external assessment

Imagine you are sitting in your home network on a machine using private ip address and is using NAT to talk to public IP address of target

Now in this case if we use Reverse shell how you will connect that Public back to your Private IP which is your home network internal IP

So you will have to then set Port forwarding on your router/firewall to talk to that Target 

So this is the extra work we will need to do 

INSTEAD we can use Bind shell and open the port on Target and connect to it

So this is how Bind shells are useful when we have to bypass firewall

# What to use

95% of time we sue reverseshell but the usage depends upon how we are connecting to target and so Bind Shell can also be useful