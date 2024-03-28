https://tryhackme.com/r/room/breachingad
https://benheater.com/tryhackme-breaching-active-directory/

DNS configuration

# Gaining First Set of AD Credentials

Two Methods

1. OSINT

OSINT is used to discover information that has been publicly disclosed.If we are lucky enough to find credentials, we will still need to find a way to test whether they are valid or not since OSINT information can be outdated. In Task 3, we will talk about NTLM Authenticated Services, which may provide an excellent avenue to test credentials to see if they are still valid.

2. Phishing

Phishing is another excellent method to breach AD. Phishing usually entices users to either provide their credentials on a malicious web page or ask them to run a specific application that would install a Remote Access Trojan (RAT) in the background. This is a prevalent method since the RAT would execute in the user's context, immediately allowing you to impersonate that user's AD account. This is why phishing is such a big topic for both Red and Blue teams.

