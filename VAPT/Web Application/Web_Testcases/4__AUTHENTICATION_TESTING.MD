# 1. Testing for Credentials Transported over an Encrypted Channel

- check if conn is https.

- check for Session token in url

# 2. Testing for bypassing authentication schema

- check for force browsing (/admin/main.php, /page.asp?authenticated=yes)

- check for parameter modification

- session id prediction

- sql injection

- username being fetched from header

# 3. Test remember password functionality

- check for password being stored in cookie, examine the cookies stored by application.

- verify the credentials are not stored cleartext

- check for Autocomplete = off


# Senerio

* IMPOROPER AUTHENTICATION

- Application uses request header to get sensitive details like user info  

The rapplication processes request header:userid (of authenticated users) sent in cleartext.

The request header are addedd to hit the application with backend url the application might process the header and could allow any user to access the application bypassing authenticationTaking 

The request header are addedd to hit the application with backend url the application might process the header and could allow any user to access the application bypassing authenticationTaking 


* IMPROPER ACCESS CONTROL FORCED BROWSING 

- login to application and paste admin url on browser session and its accessible

such flaws allow attacker to access unauthorised functionality

Most web application dosent display links and buttons to unauthorised functions, but this "presentation layer access control" dosent actully provide protection, you must also implement checks in controller or buisness logic

