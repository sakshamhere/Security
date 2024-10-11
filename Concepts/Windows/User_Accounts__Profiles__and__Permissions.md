
# User Accounts

User accounts can be one of two types on a typical local Windows system: 

`Administrator` - An Administrator can make changes to the system: add users, delete users, modify groups, modify settings on the system, etc. 
`Standard User.`- A Standard User can only make changes to folders/files attributed to the user & can't perform system-level changes, such as install programs.

There are several ways to determine which user accounts exist on the system. One way is to click the Start Menu and type Other User. A shortcut to System Settings > Other users should appear. Since you're the Administrator, you see an option to Add someone else to this PC.

Note: A Standard User will not see this option.

# Profile (C:\Users)

When a user account is created, a profile is created for the user. The location for each user profile folder will fall under is `C:\Users.`

For example, the user profile folder for the user account Max will be `C:\Users\Max.`

The creation of the user's profile is done upon initial login. When a new user account logs in to a local system for the first time

Each user profile will have the same folders; a few of them are:

    Desktop
    Documents
    Downloads
    Music
    Pictures


# Local User and Group Management.
Right-click on the Start Menu and click Run. Type `lusrmgr.msc`

you can see Users and Groups, If you click on Groups, you see all the names of the local groups along with a brief description for each group. 

Each group has permissions set to it, and users are assigned/added to groups by the Administrator. When a user is assigned to a group, the user inherits the permissions of that group. A user can be assigned to multiple groups.