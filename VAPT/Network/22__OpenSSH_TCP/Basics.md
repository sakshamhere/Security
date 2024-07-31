 # Secure Shell

The SSH protocol (also referred to as Secure Shell) is a method for `secure remote login` from one computer to another.

It protects communications security and integrity with strong encryption.

It is a secure `alternative to` the non-protected login protocols such as `(telnet, rlogin) and insecure file transfer methods (such as FTP)`.

SSH is primarily used to connect to Linux/Unix devices, as SSH usually comes as a readily installable package on most Linux distributions and can be installed in a matter of few commands. To connect securely to a Windows device, usually the remote desktop protocol (RDP) is used as it comes natively available with Windows devices.

Unix, Linux, and macOS devices have an inbuilt SSH client that allows SSH connections to be launched directly from the Terminal. for windows You can also use SSH clients like `PuTTY` to launch connections.

On the server end, the SSH server package needs to be installed and a server-side component called a `SSH daemon` or `sshd` needs to be installed and running. A SSH daemon checks for any SSH connection requests by listening to all connections on TCP port 22.

The `SSH client` drives the connection setup process and uses public key cryptography to verify the identity of the SSH server. After the setup phase the SSH protocol uses strong symmetric encryption and hashing algorithms to ensure the privacy and integrity of the data that is exchanged between the client and server.

It always comes in key pair:

`Public key` – Everyone can see it, no need to protect it. (for encryption function)
`Private key `– Stays in computer, must be protected. (for decryption function)


**************************************************************************************************************************************

# SSH Authentication

The SSH Authentication can be configured in two ways:

# 1. `Username and Password Authentication`

Password authentication is the more widely used method of authentication when establishing an SSH connection. After negotiation of shared secret and encryption, the server will prompt the user for the password of the user account that the client is trying to log in to.
Although the password is transmitted only after an encrypted connection is established, it could still be exploited by brute-forcing weak passwords, scripts, and so on. To avoid this, authentication using SSH keys is being increasingly adopted.

# 2. `Key Based Authentication using`  SSH Keys / Public Key Cryptography` / `public-key based authentication`

Key Based Authentication is a way to encrypt data, or sign data, with two different keys. One of the keys, the public key, is available for anyone to use. The other key, the private key, is kept secret by its owner. Because the two keys correspond to each other, establishing the key owner's identity requires possession of the private key that goes with the public key.

The idea is to have a cryptographic key pair - public key and private key - and configure the public key on a server to authorize access and grant anyone who has a copy of the private key access to the server. The keys used for authentication are called SSH keys.

` SSH uses public key cryptography to verify the identity of the SSH server. After the setup phase, the SSH protocol uses strong symmetric encryption and hashing algorithms to ensure the privacy and integrity of the data  `

# NOTE - In order for user to use Key-based authentication the publick key needs to be generated and copied to server that we want to access with key, then we can turn off password-based auth and become secure

- check `./working with keys`

*************************************************************************************************************************************
# Configuring Key-based authentication using OpenSSH

1. On the client system generate the public and private key par using `ssh-keygen`

2. Copy the public key `*.pub` to server using `ssh-copy-id`, note that this will be copied to `%h/.ssh/authorized_keys` file on server where %h is user's home dir

3. Now public-key authentication is configured and you can ssh into server using private key from this client system without password.

4. you can further remove the password based authentication by setting it to no in `/etc/ssh/sshd_config` file on server

*************************************************************************************************************************************
# The Working of key based authentication

SSH runs on top of the `TCP/IP` protocol suite — which much of the Internet relies upon. TCP stands for Transmission Control Protocol and IP stands for Internet Protocol. TCP/IP pairs those two protocols in order to format, route, and deliver packets. IP indicates, among other information, which IP address a packet should go to, while TCP indicates which port a packet should go to at each IP address

1. SSH session is attempted from the SSH client.

2. SSH client reaches out to the target server. The target resource could be any device that supports SSH, including remote servers, routers, and switches, among others.

3. The SSH clients gets the the public key from the SSH server, specifically from the `.ssh/authorized_keys` file.

3. The server’s public key is saved in the client’s `/etc/ssh/known hosts` file.

4. Public keys from the local computers (system) are passed to the server which is to be accessed.

5. Server then identifies if the public key is registered.

6. If so, the server then creates a new secret key and encrypts it with the public key which was send to it via local computer.

7. This encrypted code is send to the local computer.

8. This data is unlocked by the private key of the system and is send to the server.

9. Server after receiving this data verifies the local computer.

10. SSH creates a route and all the encrypted data are transferred through it with no security issues.


# Security

- SSH is key based authentication that is not prone to brute-force attack. It is more convenient and secure than login ids and passwords (which can be stolen in middle).