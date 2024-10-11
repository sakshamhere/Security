https://tryhackme.com/r/room/breachingad
https://benheater.com/tryhackme-breaching-active-directory/
# LDAP Pass-back Attacks

Very interesting attack can be performed `against LDAP authentication` mechanisms, called an `LDAP Pass-back attack.`

# `Attack possibilities`

1. we can perform LDAP Pass-back attacks  when we gain access to a device's configuration where the LDAP parameters are specified. 

1. We can also intercept the authentication attempt to recover the LDAP credentials by forcing the device to attempt LDAP authentication to our rogue device.

***************************************************************************

For this lab, we have a printer with web interface `http://printer.za.tryhackme.com/settings.aspx `

We can see username but the password is hidden, However, when we press `test settings` button , we can see that an authentication request is made to the domain controller to test the LDAP credentials. 

Let's try to intercept and exploit this to get the printer to connect to us instead, which would disclose the credentials

Since the default port of LDAP is 389, lets listen on it.