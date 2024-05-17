https://heartbleed.com/

The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. 

This weakness allows stealing the information protected, under normal conditions, by the SSL/TLS encryption used to secure the Internet. 

# The Heartbleed bug allows anyone on the Internet to read the memory of the systems protected by the `vulnerable versions of the OpenSSL` software. `

This compromises the secret keys used to identify the service providers and to encrypt the traffic, the names and passwords of the users and the actual content. This allows attackers to eavesdrop on communications, steal data directly from the services and users and to impersonate services and users.


# Affected OpenSSL versions

    OpenSSL 1.0.1 through 1.0.1f
    OpenSSL 1.0.2-beta

# Fixed versions

OpenSSL 1.0.1g has been released to address this vulnerability.  Any keys generated with a vulnerable version of OpenSSL should be considered compromised and regenerated and deployed after the patch has been applied.

Affected users should upgrade to OpenSSL 1.0.1g. 