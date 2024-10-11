https://www.redhat.com/sysadmin/etc-fstab

# /etc/fstab file

Your Linux system's filesystem table, aka `fstab`, is a configuration table designed to ease the burden of mounting and unmounting file systems to a machine.

It is a set of rules used to control how different filesystems are treated each time they are introduced to a system.

# Purpose

In the time of the ancients, users had to manually mount these drives to a file location using the `mount` command. 

The `fstab` file is designed to configure a rule where specific file systems are detected, then automatically mounted in the user's desired order every time the system boots. 