
# What is `Network BAsed Attacks`

It is something not related to Operating System but instead deals `Network` and `Network Services (services utilising network)` like below

# `ARP`

# `DHCP`

# `SMB`

# `FTP`

# `Telnet`

# `SSH`

Network based attacks is dealing with above protocols and some of the activities like password sparying and enumerating these we already saw in Host-based attacks.

In this sesction we will discuss of the `Man in the Middle Attacks (MITM)` related stuff

# Listening to traffic on a network that isnt meant for your machine

- Back in the days of `HUB` it was very easy but now when we have `SWITCH`

- Now to listen to traffic which isnt meant for our machine we need to connect to `Span Port` which listens to all the traffic on a `Switch` or we need to `Poison`, the easiest way is to `ARP Poisioning` by which we can have traffic meant for other machine come to us.

- Another thing we can do is `Promiscuous mode` where we listen to all the traffic, and if we are lucky we might even listen to traffic that is not intented for us.

