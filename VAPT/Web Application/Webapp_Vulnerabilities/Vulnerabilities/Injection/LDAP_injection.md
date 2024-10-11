# LDAP injection
best - https://www.okta.com/identity-101/what-is-ldap/

This works similar to SQLi, here instead we play around with LDAP queries, we/attacker provides LDAP query in input feilds which are not validated at the backend leading to server malicious purposes

# LDAP vs. Active Directory

Some people use LDAP and Active Directory interchangeably, and the habit causes a great deal of confusion. 

These two tools work together, but they're definitely not the same thing.

Active Directory is a proprietary directory tool that is used to organize IT assets, such as computers, printers, and users. As a Microsoft product, it’s commonly used within the Windows environment. 

`LDAP is a protocol that can read Active Directory`, but you can also use it with all kinds of products that have nothing to do with Windows.

# What is LDAP (Lightweight Directory Access Protocol)

Lightweight directory access protocol (LDAP) is a protocol that makes it possible for applications to query user information rapidly.

Companies store usernames, passwords, email addresses, printer connections, and other static data within directories. LDAP is an open, vendor-neutral application protocol for accessing and maintaining that data. LDAP can also tackle authentication, so users can sign on just once and access many different files on the server.

LDAP is a protocol, so it doesn't specify how directory programs work. Instead, it's a form of language that allows users to find the information they need very quickly.

For example, your employees may use LDAP to connect with printers or verify passwords. Those employees may then switch to Google for email, which doesn't rely on LDAP at all.

LDAP is still in widespread use today.

`People can tackle all sorts of operations with LDAP. They can: Add, Delete, Search, Compare and Modify data in database.`

Before any search commences, the LDAP must authenticate the user

# How LDAP works

An LDAP query typically involves:

1. Session connection. `The user connects to the server via an LDAP port`. 
2. Request. `The user submits a query, such as an email lookup, to the server.`
3. Response. `The LDAP protocol queries the directory, finds the information, and delivers it to the user. `
4. Completion. `The user disconnects from the LDAP port.`


The search looks simple, but a great deal of coding makes the function possible. 


# Impact
A successful exploitation of an LDAP injection vulnerability could allow the tester to:

- Access unauthorized content
- Evade application restrictions
- Gather unauthorized informations
- Add or modify Objects inside LDAP tree structure.
