https://www.youtube.com/watch?v=lp5z8HQGAH8

# Lightweight Directory Access Protocol (LDAP) authentication

`LDAP` has two main goals: one is to store data in the LDAP directory and other is to authenticate users to access the directory.

In AD the `LDAP` authentication is similar to `NTLM` authentication.

However the difference here is, with LDAP authentication, the application `directly verifies the user's credentials` instead of sending any type of challange-response to DC.

In this The application has a pair of AD credentials that it can use first to query LDAP and then verify the AD user's credentials.


# `How it works`

LDAP authentication is accomplished through a bind operation, and it follows a client/server model. 

Typically, application using LDAP must have a `LDAP Client` installed, and the server is the `LDAP directory database Server`. 

Client/Application sends a bind request to the LDAP server along with the user’s credentials which the client obtains when the user inputs their credentials

If the user’s submitted credentials match the credentials associated with their core user identity that is stored within the LDAP database, the user is authenticated and granted access to the requested resources or information through the client. If the credentials sent don’t match, the bind fails and access is denied.


                User                                          Printer (Application wth LDAP Client)                     Domain Controller

1. User sends Printing request with user Credentials ---->---->--->                    

                                            2. Printer uses its AD Credentials to create a Bind Request    ---->---->---> 

                                                                                            <---<----<-----           3. DC Provides Bind Response

                                            4. Printer request LDAP User Search            ---->---->---> 

                                                                                           <---<----<-----             5. DC provides serch response

                                            6. Printer sends Bind Request with user credentials   ---->---->---> 

                                                                                                                       7. Server sends Bind Response

Many functions are possible with LDAP, through 4 primary operators.

`Add` - Inserts a new entry into the directory-to-server database.
`Bind` -  Authenticates clients to the directory server.
`Delete` - Removes directory entires.
`Modify` - Used to request changes to existing directory entries. Changes could either be Add, Delete, or Replace operations.
`Unbind` - Terminates connections and operations in progress (this is an inverse of the Bind operation).


# `What is Attack Surface`

LDAP authentication is a popular mechanism with third-party (non-Microsoft) applications that integrate with AD. These include applications and systems such as:

- Gitlab
- Jenkins
- Custom-developed web applications
- Printers
- VPNs

If any of these applications or services are exposed on the internet, the same type of attacks as those leveraged against NTLM authenticated systems can be used. However, since a Application (with LDAP client) using LDAP authentication requires a set of AD credentials, we can attempt to recover the AD credentials used by the service to gain authenticated access to AD