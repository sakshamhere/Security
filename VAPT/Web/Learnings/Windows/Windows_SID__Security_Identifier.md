In Windows, the SID is how the operating system refers to accounts and processes instead of using an account or process name.

Each account, Group, and process, is assigned a unique `SID (Security Identifier)` to represent the security context it’s running under. 

When a User logs onto a system or executes a process, `the SID is assigned an access token` that contains everything the system needs to determine the security context, permissions, privileges, Groups, and access.