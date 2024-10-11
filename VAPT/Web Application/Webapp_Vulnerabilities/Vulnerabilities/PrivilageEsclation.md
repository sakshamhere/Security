# What is it
Privilege escalation occurs when a user gets access to more resources or functionality than they are normally allowed, and such elevation or changes should have been prevented by the application

The degree of escalation depends on what privileges the attacker is authorized to possess, and what privileges can be obtained in a successful exploit.

During this phase, the tester should verify that it is not possible for a user to modify his or her privileges or roles inside the application in ways that could allow privilege escalation attacks.

# How to test

- Testing for Role/Privilage Manipulation

In every portion of the application where a user can create information in the database,  can receive information, or delete information it is necessary to record that functionality. 

The tester should try to access such functions as another user in order to verify if it is possible to access a function that should not be permitted by the user’s role/privilege (but might be permitted as another user).

- Test for Maniplation of inputs which can lead to privilage esclation