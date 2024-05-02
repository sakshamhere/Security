https://www.youtube.com/watch?v=3FKsdbjzBcc

# We now know that in key based authentication the client has private key and server has public key `but wait!!!` from where did public key went to server

# Answer is that we/system admin configures this , he first genereates the public and private keys using `ssh-keygen` on the client

# Then he copies the `*.pub` ie the public key on server using `ssh-copy-id`, this uses the password we provide

# Now we can ssh using private key and then further disables password based authentication for security as it can be brute forced and so not secure


┌──(kali㉿kali)-[~]
└─$ `ssh-keygen -t ed25519 -f ~/.ssh/demokey -C "test comment"`
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase): `test`
Enter same passphrase again: `test`
Your identification has been saved in /home/kali/.ssh/demokey
Your public key has been saved in /home/kali/.ssh/demokey.pub
The key fingerprint is:
SHA256:J9liXaij3DDbJGG3zNRK6sxEaUUs9uVJCL7fVuV3GaA test comment
The key's randomart image is:
+--[ED25519 256]--+
|      .+o.   .   |
|     .ooo.o.. .  |
|     .Bo++oE. .. |
|     + X.Bo. o  o|
|      B S + . ..o|
|     * % * .   ..|
|      B + o      |
|         .       |
|                 |
+----[SHA256]-----+
                                                                                                                                                       

# Breaking above command

- ed25519 - This is the best public-key algorithm in generel use
- ~/.ssh/demokey - the demokey is name we given to key in home directory in /ssh
- -C "test comment"` - we can give any comment

# Now if we list /ssh in home direcotry we can see private and public key (.pub)

┌──(kali㉿kali)-[~]
└─$ `ls ~/.ssh ` 
demokey  demokey.pub  known_hosts  known_hosts.old

# Now we need to transfer this to `authorized_keys` file on our server, we can send this using `ssh-copy-id` command using password based authentication

┌──(kali㉿kali)-[~]
└─$ `ssh-copy-id -i .ssh/demokey.pub user@10.10.234.170  `
user@10.10.234.170's password: 

Number of key(s) addedd: 1

user@debian:~$

# Now the public key file is copied to server `%h/.ssh/authorized_keys ` file (`here %h mean users home dir`) also in terminal We can see the key is addedd now we can ssh using our private key and use key based authentication

# Now once are able to ssh into server using key we can disable password based auth by editing `/etc/ssh/sshd_config` on server

user@debian:~$ nano /etc/ssh/sshd_config
    # Package generated configuration file
    # See the sshd_config(5) manpage for details

    # What ports, IPs and protocols we listen for
    Port 22
    # Use these options to restrict which interfaces/protocols sshd will bind to
    #ListenAddress ::
    #ListenAddress 0.0.0.0
    Protocol 2
    # HostKeys for protocol version 2
    HostKey /etc/ssh/ssh_host_rsa_key
    HostKey /etc/ssh/ssh_host_dsa_key
    #Privilege Separation is turned on for security
    UsePrivilegeSeparation yes

    # Lifetime and size of ephemeral version 1 server key
    KeyRegenerationInterval 3600
    ServerKeyBits 768

    # Logging
    SyslogFacility AUTH
    LogLevel INFO

    # Authentication:
    LoginGraceTime 120
    PermitRootLogin yes
    StrictModes yes

    RSAAuthentication yes
    PubkeyAuthentication yes
    #AuthorizedKeysFile     %h/.ssh/authorized_keys

    # Don't read the user's ~/.rhosts and ~/.shosts files
    IgnoreRhosts yes
    # For this to work you will also need host keys in /etc/ssh_known_hosts
    RhostsRSAAuthentication no
    # similar for protocol version 2
    HostbasedAuthentication no
    # Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
    #IgnoreUserKnownHosts yes

    # To enable empty passwords, change to yes (NOT RECOMMENDED)
    PermitEmptyPasswords no

    # Change to yes to enable challenge-response passwords (beware issues with
    # some PAM modules and threads)
    ChallengeResponseAuthentication no

    # Change to no to disable tunnelled clear text passwords
    #PasswordAuthentication yes

    # Kerberos options
    #KerberosAuthentication no
    #KerberosGetAFSToken no
    #KerberosOrLocalPasswd yes
    #KerberosTicketCleanup yes

    # GSSAPI options
    #GSSAPIAuthentication no
    #GSSAPICleanupCredentials yes

    X11Forwarding yes
    X11DisplayOffset 10
    PrintMotd no
    PrintLastLog yes
    TCPKeepAlive yes
    #UseLogin no

    #MaxStartups 10:30:60
    #Banner /etc/issue.net

    # Allow client to pass locale environment variables
    AcceptEnv LANG LC_*

    Subsystem sftp /usr/lib/openssh/sftp-server

    # Set this to 'yes' to enable PAM authentication, account processing,
    # and session processing. If this is enabled, PAM authentication will
    # be allowed through the ChallengeResponseAuthentication and
    # PasswordAuthentication.  Depending on your PAM configuration,
    # PAM authentication via ChallengeResponseAuthentication may bypass
    # the setting of "PermitRootLogin without-password".
    # If you just want the PAM account and session checks to run without
    # PAM authentication, then enable this but set PasswordAuthentication
    # and ChallengeResponseAuthentication to 'no'.
    UsePAM yes

# we can change PasswordAuthentication yes to NO

# After setting it to no we can restart daemon

# `Now if user tries to sign in from any other computer/client to server than access is denied and hence our server is secure now`

# Also in production we should even change the default port 22 to some other port by editing config file above