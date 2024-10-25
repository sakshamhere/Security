References
https://www.hackthebox.com/blog/introduction-to-active-directory
https://tryhackme.com/room/winadbasics

> Active Directory Basics
- Windows Domain 
- Domain Controller
- Active Directory Domain Service
    - Active Directory data Store Schema (AD DS Schema)
    - Active Directory Domain Service data Store (AD DS data store)
- Objets
    - User
    - Machines
    - Security Groups
    - Organisational Units  (Container objects)
    - Group Policy Object

5. Authentication Methods
6. Trees, Forest and Trust Relationships (Multiple Domains)



> 
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

#### Group Policy Objects (GPO)

- So far, we have organised users and computers in OUs just for the sake of it, but the main idea behind this is to be able to deploy different policies for each OU individually. That way, we can push different configurations and security baselines to users depending on their department.

- Windows manages such policies through `Group Policy Objects (GPO)`. GPOs are simply a `collection of settings that can be applied to OUs`
- To configure GPOs, you can use the `Group Policy Management tool`, available from the start menu:

- `GPO Distribution` - GPOs are distributed to the network via a `network share` called `SYSVOL`, which is stored in the DC.

- The `SYSVOL` share points by default to the `C:\Windows\SYSVOL\sysvol\` directory on each of the DCs in our network.

- All users in a domain should typically have access to this share over the network to sync their GPOs periodically.

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


# Security Groups vs OUs

why we have both Security groups and OUs. While both are used to classify users and computers?

- Organisational Units: OUs are `handy for applying policies to users and computers, which include specific configurations that pertain to sets of users depending on their particular role in the enterprise`. Remember, `a user can only be a member of a single OU at a time`, as it wouldn't make sense to try to apply two different sets of policies to a single user.

- Security Groups, on the other hand, `are used to grant permissions over resources`. For example, you will use groups if you want to allow some users to access a shared folder or network printer. `A user can be a part of many groups`, which is needed to grant access to multiple resources.

# *****************************************************************************************************

# Delegation

One of the nice things you can do in AD is to give specific users some control over some OUs. This process is known as `delegation` and allows you to grant users specific privileges to perform advanced tasks on OUs without needing a Domain Administrator to step in.



# Authentication Methods

When using `Windows domains`, all credentials are stored in the `Domain Controllers`. 

Whenever a user tries to authenticate to a service using domain credentials, the service will need to ask the Domain Controller to verify if they are correct. 

2 protocols can be used for network authentication in windows domains:

1. `Kerberos`: `Kerberos authentication `is the default authentication protocol for any recent version of Windows.

2. `NetNTLM`: Legacy authentication protocol kept for compatibility purposes.

# ************************************************************************************************

