
# 1. Testing for Padding Oracle

Compare the reponses in three diffrent states

- Cipher text gets decrypted, resulting data is correct

- Cipher text gets decrypted, resulting data is grabbed and causes some exeption or error handeling in applicatrion logic

- Cipher text decryption fails due to paddin errors


# 2. Testing for Sensitive information sendt via uncencrypted channels

Check sensitive data during transmission

- information used in authentication (eg Credentials, PINs, Session identifiers, Tokens, Cookies)

- information protected by laws, regulations or specific organizational policy (eg Credit Cards, Customers data)

