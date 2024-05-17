
Windows can automate variety of repetative task, such as mass rollout or installation of windows os on many system.

This is typically done through `Unattended Windows Setup Utility`, this tool utilises `Configuration files` that contains specific configurations and user account credentials, specifically the Admin's account Credentials.

If the `Unattended Windows Setup configuration files` are left on the target system after installation, they can reveal credentails which attacker s can utilize for windows authentication

The `Unattended Windows System utility` will typically ustilize on of the following system configuration information:

- C:/Windows/Panther/Unattended.xml
- C:/Windows/Panther/Autounattended.xml

The password stored in them might be base64 endoded which can be decoded.