https://tryhackme.com/r/room/attackingkerberos
https://www.hackthebox.com/blog/what-is-kerberos-authentication
https://www.hackthebox.com/blog/8-powerful-kerberos-attacks

# What is Kerberos? 

Kerberos is a protocol that allows users to authenticate on the network and then access services. It is the default authentication service for Microsoft Windows domains. 

When a user logs into their PC, Kerberos is used to authenticate them. It is used whenever a user wants to access a service on the network. 

Thanks to Kerberos, a user doesn't need to type their password in constantly, and the server won't need to know every user's password. This is an example of centralized authentication.

It is intended to be `more "secure" than NTLM`, before Kerberos came, NTLM authentication resulted in a user's hash stored within memory upon authentication and If a target machine was compromised and the hash was stolen, the attacker could access anything that the user account had access to via a `Pass-The-Hash attack`.

Kerberos is a `stateless authentication protocol based on tickets`. It effectively separates a user's credentials from their requests to resources, `ensuring their password is not transmitted over the network`.

The goal of creating it was that If someone (or something) were eavesdropping on the network they wouldn’t get a hold of sensitive information. 

However Kerberos still has a handful of underlying vulnerabilities just like NTLM that we can use to our advantage.


# `The 3 Heads of Kerberos` (Principle, Resource and KDC)

1. `Principle` - The Identity that wishes to authenticate, this can be either `User Principle` (user) or `Service Principle` (service)

A `User Principal` would be a user to be authenticated, such as “Orpheus@UNDERWORLD.CORP”- In this example, Orpheus is the user with the Principal of "Orpheus" in the realm/domain  "UNDERWORLD.CORP".

A `Service Principal` represents a common service, such as an HTTP server or a file share. Consider "HTTP/hadesshares.underworld.internal@UNDERWORLD.CORP” as a Service-Principal; This specific Service Principal pertains to an HTTP server operating within the "UNDERWORLD.CORP" realm/domain.

2. `Resource`  - The resource that user or service seeks to reach after authentication

This can be either network service, systems or any data

3. `Key Distribution Center (KDC)` - The central component in Kerberos authentication

The KDC is responsible for managing authentication and distributiing session keys in a domain.

**************************************************************************************************************************

# Kerberos Tickets Overview - 

The main ticket you will receive is a `ticket-granting ticket (TGT)`. These can come in various forms, such as a .kirbi for Rubeus and .ccache for Impacket. A ticket is typically base64 encoded and can be used for multiple attacks. 

The `ticket-granting ticket` is only used to get `service tickets` from the `KDC's Ticket Granting Server (TGS)`. When requesting a TGT from the KDC, the user will authenticate with their credentials to the KDC and request a ticket. The server will validate the credentials, create a TGT and encrypt it using the krbtgt key. The encrypted TGT and a session key will be sent to the user.

When the user needs to request a service ticket, they will send the TGT and the session key to the KDC, along with the `service principal name (SPN)` of the service they wish to access. The KDC will validate the TGT and session key. If they are correct, the KDC will grant the user a service ticket, which can be used to authenticate to the corresponding service.

# Basic Understanding of Kerberos Auhthentication

Consider Victim user wants to access a service using Kerberos Authentication which is default auth in windows AD.

1. User First needs to authenticate to Authentication Service (AS) also called (KDC). It send an Authentication Request (AS-REQ) which includes NTLM hashed password and timestamp.

2. As validates the recieved credentials. It looks password hash and decrypt timestamp, If the decryption is successful and the timestamp is unique, the AS authenticates user, It recieves an Authentication Server Reply (AS-REP) from the AS. it includes 
   - TGT and a sesion key are send encrypted with password of user.
   
3. User uses his TGT to contat KDC's Ticket Granting Server (TGS) with:
   - User name and timestamp encrypted with the session key.
   - Name of the resource he’s trying to access (Service Principle Name)
   - The encrypted TGT he received upon authentication

4. KDC will Decrypt the TGT and Extract session keys from the TGT. The KDC will verify if the requested resource exist in domain and if user has permission to access it. If everything checks out, the TGS will respond with
   - Name of the service to which access has been granted
   - Session key. To be used between user and the Resource.
   - Service Ticket (ST), yes, one more ticket

5. Now that user is authenticated by the KDC, and has a session key and a service ticket (ST), he can now communicate with the service (finally!). User sends the application server an Application Request (AP-REQ), bundled with
   - Service Ticket (ST).
   - Username and timestamp encrypted with the session key.
 
6. Service Ticket (ST) is decrypted with the application server’s secret key, The Application Server checks if the AP-REQ username matches the decrypted one from the ST. Then checks if the principal (user) has privileges to use the service. If everything checks out, the application server sends an Application Server Reply (AP-REP) granting access to the requested resource.


Client/user                                        Domain Controller                                        Application Server
                                             /Key Distribution Center (KDC)                                       (AP)
                                             / Authetication Service (AS) and
                                             KDC's Ticket Granting Server (TGS)

1. Request TGT with NTLM hashed password+timestamp encrypted
   Authentication Service Request  (AS_REQ)
------------------------------------------->
    
2. Recieves TGT + session key encrypted with with user password hash
   Authentication Service Response (AS_REP)
<------------------------------------------

3. User uses his TGT to contat KDC's Ticket Granting Server (TGS) with:
   - User name and timestamp encrypted with the session key.
   - Name of the resource he’s trying to access (Service Principle Name)
   - The encrypted TGT he received upon authentication
                                   (TGS_REQ)
------------------------------------------->

4. The TGS will respond with
   - Name of the service to which access has been granted
   - Session key. To be used between user and the Resource.
   - Service Ticket (ST), yes, one more ticket  
                                    (TGS_REP)
<------------------------------------------

5. User sends the application server an Application Request (AP-REQ), bundled with
   - Service Ticket (ST).
   - Username and timestamp encrypted with the session key.
                                     (AP-REQ)
------------------------------------------------------------------------------------------------------->
   
   
6. User can now authenticate himself to the Application server and establish a secure session using the session key included in the AP-REP. 
                                     (AP-REP)
<---------------------------------------------------------------------------------------------------

# *****************************************************************************************************************************

# 1. The client requests an Authentication Ticket or Ticket Granting Ticket (TGT).

The user sends their NTLM hash and a timestamp encrypted to `Key Distribution Center (KDC),`

The KDC attempts to decrypt the timestamp using the NT hash from the user, if successful the KDC will issue a `TGT` as well as a `session key `for the user.

*********************************************************************************************************************

# 2. The KDC Key Distribution Center verifies the client and sends back an encrypted TGT.

The `ticket-granting ticket` is only used to get `service tickets` from the KDC. 

When requesting a `TGT` from the `KDC`, the user will authenticate with their credentials to the KDC and request a ticket. 



*********************************************************************************************************************

# 3. The client sends the encrypted TGT to the Ticket Granting Server (TGS) with the Service Principal Name (SPN) of the service the client wants to access. 

When the user needs to access any application/service they request a `service ticket`, they will send the `TGT` and the `session key` to the KDC, along with the `service principal name (SPN) of the service` they wish to access. 

When a user wants to connect to a service on the network like a share or application server, website or database, they will use their `TGT` to ask the `KDC Ticker Grating Server` for a Service Tiket 

`Service Principal Name (SPN)`, SPN Indicates the service and server name victim intend to access.

*********************************************************************************************************************

# 4. The Key Distribution Center (KDC) verifies the TGT of the user and that the user has access to the service, then sends a TGT encrypted with Serivice Owners account password hash

The `KDC's Ticket Granthing Server (TGS)` will validate the TGT and session key. If they are correct, the KDC will grant the user a `service ticket`, which can be used to authenticate to the corresponding service.

Basically by service ticket we mean that The `KDC` will send back encrypted TGT using requested `Service Owner's` account's password hash with a session key

# 5. Client Presents encrypted TGS + session key to the service for aceess

# 6. Finally the Service grants access to user/client

********************************************************************************************************************
********************************************************************************************************************