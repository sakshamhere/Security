https://www.hackthebox.com/blog/introduction-to-active-directory
https://tryhackme.com/room/winadbasics


# Active Directory Basics

## Active Directory History

- LDAP, the foundation of AD, was first introduced in 1971.
- The first beta release of Active Directory was in 1997, but it was not integrated into the Windows operating system until Windows Server 2000 was released. Each subsequent release of Windows Server saw added functionality and improvements in administration.
- Windows Server 2003 introduced the `Forest` feature, which gave sysadmins the ability to create "containers," or groupings, of separate domains, users, computers, groups, and other objects.
- Server 2008 saw the debut of `Active Directory Federation Services (ADFS)`, which provides Single Sign-On (SSO) to systems and applications for users using Windows Server operating systems. ADFS streamlined the process of signing into applications and systems on a different LAN, allowing them to access organizations across organizational boundaries with a single set of credentials. 
- Server 2016 brought even more changes to AD, including `functionality for migrating AD environments to the cloud` and further security enhancements such as user access monitoring and Group Managed Service Accounts (gMSA). Group Managed Service Accounts offer a more secure way to run automated tasks, applications, and services. By design, they use very complex passwords, automatically rotate on a set interval (like machine accounts), and are a key mitigation against the infamous Kerberoasting attack. This release also brought a more significant push toward the cloud with the inclusion of Azure AD Connect as an SSO method for users being migrated to Microsoft Office 365.

## Key Components

### Windows Domain 

Consider small business network with only 5 computers and 5 employees. In such a tiny network, you will probably be able to configure each computer separately without a problem.
Now What if your business suddenly grows and now has 157 computers and 320 different users located across four different offices. In such case we use `Windows Domain`

- It is a group of users and computers under the administration of a given business.
- It is used to centralise the administration of users and computers of Windows computer network in a single repository called `Active Directory (AD)`
- The server that runs the these Active Directory services is known as a `Domain Controller (DC).`
- Key uses of `Windows Domain` :-
    - `Centralised identity management`: All users across the network can be configured from Active Directory with minimum effort.
    - `Managing security policies`: You can configure security policies directly from Active Directory and apply them to users and computers across the network as needed.

- Example:

    - In a corporate you will often be provided with a username and password that you can use on any of the computers available. Your credentials are valid for all machines because whenever you input them on a machine, it will forward the authentication process back to the Active Directory, where your credentials will be checked. Thanks to Active Directory, your credentials don't need to exist in each machine and are available throughout the network.

    - Secondly you might also notice that you are not able to make Administrative changes on those machines,  this is because of policies that are being enforced using AD.

    - Suppose you are logging into a machine uaing a username `THM\Administrator` then THM is the windows domain you are using.

### Domain Controller

The server that runs the Active Directory Domain services is known as a `Domain Controller (DC).`
- It Hosts copy of AD Directory store
- It Provides Authentication and Authorisation Services
- It Replicates updates to other domain controllers in domain and forest
- Allows Administrative access to manage user accounts and network resources


### Active Directory Domain Service (AD DS), Schema and Data Store

- `AD DS` is the core of Windows Domain. This service acts as a catalogue that holds the information of all of the "objects"(`users, groups, machines, printers, shares and many others`) that exist on your network.

- `AD DS Schema`, AD DS Schema is basically a blueprint of every object that can be created in AD

    - It defines every type of object that can be stored in the directory

    - It Enforces rules regarding object creation and configuration

- `AD DS Data Store`, AD DS data store contains the database files and processes that store and manage directory information for users, services and applications.
    - It contains sensitive file `Ntds.dit` (contains `Password Hashes of users` in that domain)

### Objects 
#### Security Principals
##### Users
- For every user that joins Active Directory domain , a user object will be created. User objects which are also known as `security principals`.

- These `Users / Security Principals` can be authenticated by the domain and can be assigned privileges over resources like files or printers.

- Users can be used to represent two types of entities (`People user and Service user`):

    - `People`: users will generally represent persons in your organisation that need to access the network, like employees.

    - `Service`: we can also define users to be used by services like IIS or MSSQL, these `service users` are different from regular users as they will only have the privileges needed to run their specific service.


##### Machines 

- For every computer that joins the Active Directory domain, a machine object will be created. Machines are also considered as `security principals`.

- These `machine objects ` are assigned an `Machine Account` just as any regular user. This `Machine Account` has somewhat limited rights within the domain itself.

- These `Machine Account` are local administrators on the assigned computer, they are generally not supposed to be accessed by anyone except the computer itself, but as with any other account, if you have the password, you can use it to log in.

- Machine Account passwords are automatically rotated out and are generally comprised of 120 random characters

- Identifying machine accounts is relatively easy. They follow a specific naming scheme. The machine account name is the computer's name followed by a dollar sign. `For example, a machine named `DC01 `will have a machine account called `DC01$``.


##### Security Groups 

- Security Groups basically provides privileges , these are to assign access rights to files or other resources to a group of `Users or Machines`.
Security Groups are also considered as `Security Principals`.

- Groups can have both users and machines as members.

- There are many groups created by default in a `Windows Domain` Some of the most `Privileged important groups` in a Domain are :-

    - `Domain Admins` 
        - Users of this group have `administrative privileges for the entire domain`. By default, they can administer any computer on the domain, including the DCs.

    - `Server Operators`
        - Users in this group have `administrative privileges for Domain Controllers`. They cannot change any administrative group memberships.

    - `Backup Operators`	
        - Users in this group are allowed to `access any file in Domain`, ignoring their permissions. They are used to perform backups of data on computers.

    - `Account Operators`
        - Users in this group can `create or modify other accounts in the domain`.

    - `Domain Users`
        - Includes all existing user accounts in the domain.

    - `Domain Computers`
        - Includes all existing computers in the domain.

    - `Domain Controllers`
        - Includes all existing DCs on the domain.

- All these objects (Users, Machines and groups) in domain are organised in `Organizational Units`


#### Container Objects
##### OUs (Organizational Units)
- All these objects (Users, Machines and groups) in domain are organised in `Organizational Units` which are `container objects` that allow you to classify users and machines.

- OUs are mainly used to define sets of users with similar policing requirements.

- For example The people in the Sales department of your organisation are likely to have a different set of policies applied than the people in IT.

- Note that a user can only be a part of a single OU at a time.

- OUs can have multiple child OUs

- There are some `Default OUs` / Containers created by Windows automatically as mentioned below:

    - `Builtin:` 
        - Contains default groups available to any Windows host.

    - `Computers: `
        - Any machine joining the network will be put here by default. You can move them if needed.

    - `Domain Controllers:` 
        - Default OU that contains the DCs in your network.

    - `Users:` 
        - Default users and groups that apply to a domain-wide context.

    - `Managed Service Accounts:` 
        - Holds accounts used by services in your Windows domain.

###### Security Groups vs OUs

why we have both Security groups and OUs. While both are used to classify users and computers?

- Organisational Units: OUs are `handy for applying policies to users and computers, which include specific configurations that pertain to sets of users depending on their particular role in the enterprise`. Remember, `a user can only be a member of a single OU at a time`, as it wouldn't make sense to try to apply two different sets of policies to a single user.

- Security Groups, on the other hand, `are used to grant permissions over resources`. For example, you will use groups if you want to allow some users to access a shared folder or network printer. `A user can be a part of many groups`, which is needed to grant access to multiple resources.


#### Group Policy Objects (GPO)

- So far, we have organised users and computers in OUs just for the sake of it, but the main idea behind this is to be able to deploy different policies for each OU individually. That way, we can push different configurations and security baselines to users depending on their department.

- Windows manages such policies through `Group Policy Objects (GPO)`. GPOs are simply a `collection of settings that can be applied to OUs`
- To configure GPOs, you can use the `Group Policy Management tool`, available from the start menu:

- `GPO Distribution` - GPOs are distributed to the network via a `network share` called `SYSVOL`, which is stored in the DC.

- The `SYSVOL` share points by default to the `C:\Windows\SYSVOL\sysvol\` directory on each of the DCs in our network.

- All users in a domain should typically have access to this share over the network to sync their GPOs periodically.

###### SYSVOL

Any AD account, no matter how low-privileged, can read the contents of the SYSVOL directory.

SYSVOL is a folder that exists on all domain controllers. It is a shared folder storing the Group Policy Objects (GPOs) and information along with any other domain related scripts. 

It is an essential component for Active Directory since it delivers these GPOs to all computers on the domain. 

Domain-joined computers can then read these GPOs and apply the applicable ones, making domain-wide configuration changes from a central location.

### Multiple Domains

Having a single `Windows domain` for a company is good enough to start, but in time some additional needs might push you into having more than one.
For Example suddenly your company expands to a new country. The new country has different laws and regulations that require you to update your `GPOs` to comply.While you could create a complex `OU` structure and use `delegations` to achieve this, but having a huge AD structure might be hard to manage and prone to human errors.

Luckily for us, `Active Directory supports integrating multiple domains` so that you can partition your network into units that can be managed independently.

#### Trees
Domains can be joined into a Tree.

                                                                     DC-Root
                                                                   (thm.local)
                                                                  /           \
                                                                 /             \
                                                                /               \
                                                        DC-UK                       DC-US
                                                    (uk.thm.local)                  (us.thm.local)
    

The IT people from the UK will have their own DC that manages the UK resources only, For example, a UK user would not be able to manage US users. In that way, the Domain Administrators of each branch will have complete control over their respective DCs, but not other branches' DCs


#### Forests

Suppose your company continues growing and eventually acquires another company called `MHT Inc`. 

When both companies merge, you will probably have different domain trees for each company, each managed by its own IT department. The union of several trees with different namespaces into the same network is known as a forest.

                                         DC-Root  <<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>> DC-Root
                                       (thm.local)                                                (mht.local)
                                      /           \                                               /         \  
                                     /             \                                             /           \
                                    /               \                                           /             \
                        DC-UK                       DC-US                               DC-Europe              DC- Asia
                    (uk.thm.local)                  (us.thm.local)                    (eu.mht.local)           (asia.mht.local)


#### Trust Relationships

At a certain point, a user at THM UK might need to access a shared file in one of MHT ASIA servers. For this to happen, domains arranged in trees and forests are joined together by trust relationships.



# Active Directory Authentication Methods

When using `Windows domains`, all credentials are stored in the `Domain Controllers`. 
Whenever a user tries to authenticate to a service using domain credentials, the service will need to ask the Domain Controller to verify if they are correct. 

2 protocols can be used for network authentication in windows domains:
1. `Kerberos`: `Kerberos authentication `is the default authentication protocol for any recent version of Windows.
2. `NetNTLM`: Legacy authentication protocol kept for compatibility purposes.

## Kerberos Authentication (KRTGT)
https://www.youtube.com/watch?v=OuJe0d1NGaM
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/b4af186e-b2ff-43f9-b18e-eedb366abf13
https://www.hackthebox.com/blog/what-is-kerberos-authentication#the_three_heads_of_kerberos_authentication_kdc_realms__tickets

Okay, so we have our three parties: 
1. The client/user (Service Principal)
2. The application server / service
3. the trusted third party KDC (Key Distribution Center)
    - AS (Authentication Service)
    - TGS (Ticket Granting Service)

Kerberos Communication Flow:

1. First when user logs in workstation it provides its username and password, the current timestamp is encrypted with passwords NTLM hash this encrypted timestamp and other pre-authentication details is then sent to to KDC's Authentication Service (AS).

Client/user sends AS_REQ to KDC, it presents its user principal name (UPN), encrypted timestamp and pre-authentication details, The AS will then verify by decrypting timestamp from user's hash in DC and verify other preauthentication details,  if its legitimate user it will respond back with a Ticket Granting Ticket (TGT) with a session key,  this session key is encrypted with user's NT hash., this is AS_REP. The user can use this TGT and sesion key to have an encrypted communication further with KDC, this authentication with KDC's Authentication Service only takes one time, since it provides the session key which can be used multiple time by service principal.

2. Now if client/user wants to access any service (Say SMB share), he will now request to KDC's Ticket Granting Service(TGS) to provide a Service Ticket for the service.

Client/user will send TGS_REQ to KDC , its current TGT along with a Service Prinicipal Name (SPN) of service for which it wants service ticket. The KDC's TGS will validate TGT presented and if everything is fine it will response TGS_REP with the service tciket encrypted with NTLM hash of service account, the client can then use this service ticket to connect with the server which has Service for which it requested service ticket.

3. Now client/user can present the service ticket to the service/server it wants to access. The service/server will decrypt the ticket and validate it. If thins are fine then it grants the access.


![alt text](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/ms-kile_files/image001.png)


### KRTGT vs NetNTLM
With NTLM authentication, the hashed user password is stored on the client, the DC, and the application server, and an application server would have to coordinate directly with the DC to validate access. It’s everywhere and someone with a tool like `mimikatz` could certainly grab that password from any of those locations and make hay.

With KRBTGT, the hash isn’t stored in memory across as many systems, making the theft of a KRBTGT password much more difficult.

To have full unfettered access, a user would have to gain access to the KDC on the DC and steal the password to create a Golden Ticket

### Forced NTLM (IP vs Hostnames)
Question: `Is there a difference between `dir \\za.tryhackme.com\SYSVOL` and `dir \\<DC IP>\SYSVOL` and why the big fuss about DNS?`

There is quite a difference, and it boils down to the authentication method being used. 

When we provide the hostname (FQDN), network authentication will attempt first to perform Kerberos authentication. Since Kerberos authentication relies on fully qualified domain names (FQDN), because the FQDN of the service is referenced directly in the ticket. 

In Active Directory environments where Kerberos authentication uses hostnames/FQDN embedded in the tickets, if we provide the IP instead, we can force the authentication type to be NTLM. 

NTLM is so heavily integrated into Microsoft products that in most cases it's going to be running side-by-side with Kerberos.

While on the surface, this does not matter to us right now, it is good to understand these slight differences since they can allow you to remain more stealthy during a Red team assessment. 

In some instances, organisations will be monitoring for OverPass- and Pass-The-Hash Attacks. 

Forcing NTLM authentication is a good trick to have in the book to avoid detection in these cases.


## Lightweight Directory Access Protocol (LDAP) authentication

`LDAP` has two main goals: one is to store data in the LDAP directory and other is to authenticate users to access the directory.
In AD the `LDAP` authentication is similar to `NTLM` authentication.
However the difference here is, with LDAP authentication, the application `directly verifies the user's credentials` instead of sending any type of challange-response to DC.

In this The application has a pair of AD credentials that it can use first to query LDAP and then verify the AD user's credentials.


`How it works`

LDAP authentication is accomplished through a bind operation, and it follows a client/server model. 

Typically, application using LDAP must have a `LDAP Client` installed, and the server is the `LDAP directory database Server`. 

Client/Application sends a bind request to the LDAP server along with the user’s credentials which the client obtains when the user inputs their credentials

If the user’s submitted credentials match the credentials associated with their core user identity that is stored within the LDAP database, the user is authenticated and granted access to the requested resources or information through the client. If the credentials sent don’t match, the bind fails and access is denied.

```
                User                                          Printer (Application wth LDAP Client)                     Domain Controller

1. User sends Printing request with user Credentials ---->---->--->                    

                                            2. Printer uses its AD Credentials to create a Bind Request    ---->---->---> 

                                                                                            <---<----<-----           3. DC Provides Bind Response

                                            4. Printer request LDAP User Search            ---->---->---> 

                                                                                           <---<----<-----             5. DC provides serch response

                                            6. Printer sends Bind Request with user credentials   ---->---->---> 

                                                                                                                       7. Server sends Bind Response
```
Many functions are possible with LDAP, through 4 primary operators.

`Add` - Inserts a new entry into the directory-to-server database.
`Bind` -  Authenticates clients to the directory server.
`Delete` - Removes directory entires.
`Modify` - Used to request changes to existing directory entries. Changes could either be Add, Delete, or Replace operations.
`Unbind` - Terminates connections and operations in progress (this is an inverse of the Bind operation).


`What is Attack Surface`

LDAP authentication is a popular mechanism with third-party (non-Microsoft) applications that integrate with AD. These include applications and systems such as:

- Gitlab
- Jenkins
- Custom-developed web applications
- Printers
- VPNs

If any of these applications or services are exposed on the internet, the same type of attacks as those leveraged against NTLM authenticated systems can be used. However, since a Application (with LDAP client) using LDAP authentication requires a set of AD credentials, we can attempt to recover the AD credentials used by the service to gain authenticated access to AD

## NetNTLM

`New Technology LAN Manager (NTLM)` is the suite of security protocols used to authenticate users' identities in AD.
`NetNTLM` - NTLM can be used for authentication by using a `challenge-response-based scheme` called `NetNTLM`.

`How it Works?`

NTLM Authentication allows the application to play the role of a middle man between the client and AD.

All authentication material is forwarded to a Domain Controller in the form of a challenge by application, and if completed successfully, the application will authenticate the user. 

This means that the application is authenticating on behalf of the user and not authenticating the user directly on the application itself.

The is good as This prevents the application from storing AD credentials, which should only be stored on a Domain Controller.
```

                User                                          Application Server                                          Domain Controller

    1. User sends access request     ---->---->--->                    

                                     <---<----<-----       2. Server sends Challange

    3. User sends Response           ---->---->--->        4. Server sends both Challange and Response   ---->---->--->  5. DC compares both Challange and 
                                                                                                                            Response for Authentication

                                      <---<----<-----       2. Server sends DC's response               <---<----<-----  6. DC Sends response (valid or 
                                                                                                                                               invalid)

```
This authentication mechanism is heavily used by the services on a internal network. However, services that use NetNTLM can also be exposed to the internet For Example:

- `Internally-hosted Exchange (Mail) servers` that expose an Outlook Web App (OWA) login portal.

- `Remote Desktop Protocol (RDP)` service of a server being exposed to the internet.

- Exposed `VPN endpoints` that were integrated with AD.

- `Web applications` that are internet-facing and make use of NetNTLM.

# Delegations
Delegations enables you to grant users/services the permissions to perform tasks that require elevated permissions.

## Active Directory delegation

For Example Help Desk group is given permission to reset passwords for users. this is a type of active directory delegation.

## Kerberos Delegation
https://learn.microsoft.com/en-us/archive/blogs/autz_auth_stuff/kerberos-delegation

Kerberos delegations allow services to access other services on behalf of domain users.

Kerberos Delegation is a feature that allows an application to reuse the end-user credentials to access recourses hosted on a different server. You should only allow that if you really trust the application server, otherwise the application may use your credentials to purposes that you didn't think of, like sending e-mails on your behalf or changing data in a mission critical application pretending that you made that change.

For that reason, delegation is not enabled by default in Active Directory. You - or more likely the domain administrator - must explicit make the decision that this particular application is trusted for delegation. 

The practical use of Kerberos delegation is to enable an application to access resources hosted on a different server. For example an application, such as a web server, needs to access resources for the website hosted somewhere else, such as a SQL database you can allow that service account to be delegated to the SQL server service. Once a user logs into the website, the service account will request access to the SQL server service on behalf of that user. This allows the user to get access to the content in the database that they’ve been provisioned to, without having to provision any access to the web server’s service account itself.

