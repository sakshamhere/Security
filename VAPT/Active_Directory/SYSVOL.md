# SYSVOL

Any AD account, no matter how low-privileged, can read the contents of the SYSVOL directory.

SYSVOL is a folder that exists on all domain controllers. It is a shared folder storing the Group Policy Objects (GPOs) and information along with any other domain related scripts. 

It is an essential component for Active Directory since it delivers these GPOs to all computers on the domain. 

Domain-joined computers can then read these GPOs and apply the applicable ones, making domain-wide configuration changes from a central location.