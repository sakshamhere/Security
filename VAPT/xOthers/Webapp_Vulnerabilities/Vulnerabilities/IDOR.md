# What is IDOR (Insecure Direct Object Reference)   https://www.youtube.com/watch?v=rloqMGcPMkI

IDOR is a type of Access Control vulnerability that arises when application uses user supplied input to direcly access object

IDOR means that an application directly exposes reference to an object like user detail/file or anything, which can be directly accessd regardless of authorization

# Example

Consider a website with a URL to access a customer account page where the customer number is direcly uesd as record index in query

                        https://insecure-website.com/customer_account?customer_number=132355

An Attacker can simply modify the customer number to some other and bypass access control to view information of other customer.

He can perform horizontal and vertical privilage esclations.

He can also peforom other exploits like password leakage or modifying parameter after getting to users account page.

# Why is happen

A direct object reference occurs when a developer exposes a reference to an internal implementation object, such as a file, directory, database record, or key, as a URL or form parameter.

Direct Object Reference is fundamentally a Access Control problem. it's the Access Control issue that "allows" the attacker to access the object for which they have guessed the identifier through the enumeration attack.

# Impact

- Unauthorized information disclosure

- Modification or destruction of data

- Performing a function outside limits of data of user

# Prevent

- Enforce Access Control Policies such that user cannot act outside of their intended permissions

- Use a hash to replace the direct identifier.Use Hash function and hashed values instead of normal numbers or strings

JWT - JSON Web Object https://www.youtube.com/watch?v=5mUDRQfwXuE

# Test  IDOR

To test for this vulnerability the tester first needs to map out all locations in the application where user input is used to reference objects directly For example, locations where user input is used to access a database row, a file, application pages and more.

Next the tester should modify the value of the parameter used to reference objects and assess whether it is possible to retrieve objects belonging to other users or otherwise bypass authorization.

- The Value of a Parameter Is Used Directly to Retrieve a Database Record
Sample request:

http://foo.bar/somepage?invoice=12345

- The Value of a Parameter Is Used Directly to Perform an Operation in the System
Sample request:

http://foo.bar/changepassword?user=someuser

- The Value of a Parameter Is Used Directly to Retrieve a File System Resource
Sample request:

http://foo.bar/showImage?img=img0001

- The Value of a Parameter Is Used Directly to Access Application Functionality
Sample request:

http://foo.bar/accessPage?menuitem=12