

`/etc/passwd` - not so sensitive as it dosent give password but gives information of user present on linux system

`/etc/shadow `- this proivides the hash of users password and can be accessed by root privileges only

`/etc/sudoers` - The sudoers file instructs the system how to handle the sudo command (what can each sudo user do).  

`/etc/init.d` - This dir contains all `System V` init scripts.

`/etc/issue` - This file usually contains some information about the operating system 

`/proc/version`  - This may give you information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed. 


`/etc/crontab` - Any user can read the file keeping system-wide cron jobs under /etc/crontab

`/etc/fstab` - The `fstab` file is designed to configure a rule where specific file systems are detected, then automatically mounted in the user's desired order every time the system boots. 

`/etc/ssh` -  System-wide SSH configuration information is stored in the /etc/ssh/ directory

`/etc/ssh/sshd_config` - we can manage SSH config for machine using this