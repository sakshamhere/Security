# Simple Network Management Protocol
https://www.youtube.com/watch?v=Lq7j-QipNrI


SNMP is protocol used to collect and organize device information on a network and it does this over `UDP port 161`

A device that has SNMP enabled is called an `Agent`, an Agent has several `objects` that can be interaceted with

For example a device say router in this case has objects for 
- Name
- Uptime
- Interfaces
- Routing Table

Each object is assigned a Object Identifier or `OID`, OId is a sequence of numner which looks like IP address

  object            OID
- Name              1.2.5..3.5.3.45.
- Uptime            1.2.5..3.5.3.45.
- Interfaces        1.2.5..3.5.3.45.
- Routing Table     1.2.5..3.5.3.45.

These `OID`s are stored in a file called `MIB` or Management Information Base

The MIB has a tree structure and tells the agent the exact location of the Object.

But to interact with these objects we need something called Network Management Syste or `NMS`, NMS is a piece of software that can communicate with SNMP Agent

The NMS interact with Agent using Following requests

`GET request` -         NMS can do a GET request to Agent like what is your name
`SET request` -         NMS can do a SET request to Agent like change your name to 'xyz'
`TRAP/INFORM request` - Agents use TRAP/INFORM to communicate back to NMS, These are useful for monitoring critical events, agent sends a     
                        TRAP/INFORM when an event occour on device for example when an interface goes down etc
                        TRAP and INFORM both serve same purpose

SNMP is built for administrators to:

1. Monitor the network

- Monitor if a network interface is up/down
- Monitor network bandwitdh
- Monitor CPU Usage
- Monitor Even the tempreture of devices

2. Remotely modify settings and configurations on equipments/devices