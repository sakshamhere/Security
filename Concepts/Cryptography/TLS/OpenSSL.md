https://www.digicert.com/kb/ssl-support/openssl-quick-reference-guide.htm#:~:text=OpenSSL%20is%20an%20open%2Dsource,certificate%2C%20and%20identify%20certificate%20information.



OpenSSL is an open-source command line tool that is commonly used to generate private keys, create certificate signing request (CSR), install your SSL/TLS certificate, and identify certificate information

Use the following command to identify which version of OpenSSL you are running:

`openssl version -a`

> Steps to obtain a SSL Certificate

1. Decide the private key options (algoritm, size and passphrase)

2. generate a private key PEM file

3. generate a public key using same PEM (if you want)

4. Create a CSR (Certificate Signing Request)

5. Send the CSR to CA/Certificate Authority (eg digicert, Let's encrypt)


# Steps to obtain a SSL certificate 

The first step to obtaining an SSL certificate is using OpenSSL to create a certificate signing request (CSR) that can be sent to a Certificate Authority (CA) (e.g., DigiCert)

The CSR contains the common name(s) you want your certificate to secure, information about your company, and your public key. In order for a CSR to be created, it needs to have a private key from which the public key is extracted. This can be done by using an existing private key or generating a new private key.

Security Note: Because of the security issues associated with using an existing private key, and because it's very easy and entirely free to create a private key, we recommend you generate a brand new private key whenever you create a CSR

# 1. Deciding on Key Generation Options

When generating a key, you have to decide three things: the key algorithm, the key size, and whether to use a passphrase.

` Key algorithm`
` key size`
` passphrase`

1. Choose key algorithm

RSA is recommended, However, if you have a specific need to use another algorithm (such as ECDSA), you can use that too, but be aware of the compatibility issues you might run into.

2. Key Size

Select a bit length of at least 2048 when using RSA 

256 when using ECDSA

if no key size is specified, the default key size of 512 is used

NOTE - Any key size lower than 2048 is considered unsecure and should never be used.

3. Passphrase

For the passphrase, you need to decide whether you want to use one.

# 2. Generating Private key

After deciding on a key algorithm, key size, and whether to use a passphrase, you are ready to generate your private key.

Use the following command to generate your private key using the RSA algorithm:

`openssl genrsa -out yourdomain.key 2048`

This command generates a private key in your current directory named yourdomain.key (-out yourdomain.key) using the RSA algorithm (genrsa) with a key length of 2048 bits (2048). The generated key is created using the OpenSSL format called PEM.

# 3. Extracting Your Public Key

The private key file contains both the private key and the public key. You can extract your public key from your private key file if needed.

Use the following command to extract your public key:

`openssl rsa -in yourdomain.key -pubout -out yourdomain_public.key`

# 4. Creating Your CSR (certificate signing request)

After generating your private key, you are ready to create your CSR. The CSR is created using the PEM format and contains the public key portion of the private key as well as information about you (or your company).

Use the following command to create a CSR using your newly generated private key:

`openssl req -new -key yourdomain.key -out yourdomain.csr`

# Sending the CSR to the CA (e.g., DigiCert)

When you are ready to send the CSR to the CA (e.g., DigiCert), you need to do so using the PEM format—the raw, encoded text of the CSR that you see when opening it in a text editor.

Use the following command to view the raw output of the CSR:

`cat yourdomain.csr`

You must copy the entire contents of the output (including the -----BEGIN CERTIFICATE REQUEST----- and -----END CERTIFICATE REQUEST----- lines) and `paste it into your DigiCert order form`.