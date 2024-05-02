
# Role-Based Access Control on Hosts

Role-based access control allows you to indicate access privileges at different levels. It includes DNS zone, server, or resource record levels and specifies who has access control over creating, editing, and deleting operations of various resources of Active Directory. 

# Tiered Access Model

The Active Directory Tiered Access Model (TAM) comprises plenty of technical controls that reduce the privilege escalation risks

Tier 0: Top level and includes all the admin accounts, Domain Controller, and groups.
Tier 1: Domain member applications and servers. 
Tier 2: End-user devices like HR and sales staff (non-IT personnel).

Implementation is done by GPO Group policy objects, These Group Policy Objects put together the security rights that can deny access or grant permission.

# Auditing Accounts 

Accounts audit is a crucial task mainly carried out by setting up the correct account, assigning privileges, and applying restrictions. Three audit types related to accounts must be done periodically: usage, privilege, and change audits. 

- Usage audits allow monitoring each account's specific tasks and validating their access rights. 

- A privilege audit allows you to check if every account in the system has the least privilege.

- Change audits allow you to look for any improper changes to account permissions, passwords, or settings. Any unacceptable change to these may lead to a data breach.