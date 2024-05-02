# CertUtil 
is a very powerful tool that allows administrators to manage certificates and certificate stores on Windows operating systems. It provides a range of features and functionalities, including the ability to view certificates, verify digital signatures, and manage.


# How attackers uses certutil.exe:

According to Malwarebyte report in a attack against Saudi Arabia Government, The payload was embedded in a macro as Base64 code. It uses the certutil program to decode the Base64 into a PE file. The ‘Retefe Trojan’ writes the root certificate to the disk and then uses the above given commands to install it on the system. 

`Certutil.exe used to download and decode remote files`. Sofacy has used Certutil to attack multiple government entities. Attackers also can use CertUtil to `encode or decode malicious payloads while avoiding detection`.