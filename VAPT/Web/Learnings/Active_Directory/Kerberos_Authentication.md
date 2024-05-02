https://tryhackme.com/room/winadbasics

# Kerberos Authentication

`Kerberos authentication `is the default authentication protocol for any recent version of Windows.

Users authenticated via kerberos are assigned Tickets, they can provide present these tickets to services as a proof of being authenticated.

When Kerberos is used for authentication, the following process happens:

1. The user sends their username and a timestamp encrypted using a key derived from their password to the `Key Distribution Center (KDC),`

`Key Distribution Center (KDC),` -  A Service usually installed on the Domain Controller in charge of `creating Kerberos tickets` on the network.

The `KDC` will create and send back a `Ticket Granting Ticket (TGT)`, which will allow the user to request additional tickets to access specific services.
Ticket to get more tickets may sound a bit weird, but it allows users to request service tickets without passing their credentials every time they want to connect to a service.

Along with the `TGT`, a `Session Key` is given to the user, which they will need to generate the following requests.

# `krbtgt account`

`TGT` is encrypted using the `krbtgt account's password hash`, and therefore the user can't access its contents.

It is essential to know that the `encrypted TGT` includes a `copy of the Session Key` as part of its contents, and the `KDC` has no need to store the `Session Key` as it can recover a copy by decrypting the TGT if needed.

USER HASH - Encrypted (Username + Timestamp) by key derived from Password

 
        USER                                                                 KDC (Domain Controller)

                                    TGT Request
    User Hash ------>------------->------------>---------->----------->------->

                                     RESPONSE
              <------<-------------<------------<----------<-----------<--------Encrypted (TGT + Session Key) using `Krbtgt` account's password hash




2. When a user wants to connect to a service on the network like a share, website or database, they will use their `TGT` to ask the `KDC` for a `Ticket Granting Service (TGS).`

`Ticket Granting Service (TGS).` - `TGS` are tickets that allow connection only to the specific service they were created for. The TGS is encrypted using a 
                                    key derived from the `Service Owner Hash`.
                                    `Service Owner Hash` - The Service Owner is the user or machine account that the service runs under. 


To request a TGS, the user will send their `username and a timestamp encrypted using the Session Key`, along with the `TGT` and a `Service Principal Name (SPN)` to `KDC`.

`Service Principal Name (SPN)` - SPN Indicates the service and server name we intend to access.

As a result, the `KDC` will send us a `TGS` along with a `Service Session Key`, which we will need to authenticate to the service we want to access.

The `TGS `contains a copy of the `Service Session Key` on its encrypted contents so that the `Service Owner` can access it by decrypting the `TGS`.


        USER                                                                                              KDC (Domain Controller)

                                                                   TGS Request
TGT+ Session Key + Service Principal Name ------>------------->------------>---------->----------->------->

                                                                   RESPONSE
                                       <------<-------------<------------<----------<-----------<--------Encrypted (TGS) using Service Owner account's 
                                                                                                           password hash + Service Session Key


The `TGS `can then be sent to the desired service to authenticate and establish a connection