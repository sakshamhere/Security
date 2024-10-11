# Disable email sharing during Facebook login and be ready for unusual design flows that could enable you to take over other users' accounts.
https://x.com/Jayesh25_/status/1725810970423865466?s=20

Here's how to disable email sharing when using "Login with Facebook": 

1️⃣ Log in with Facebook on any app. 
2️⃣ Click "Edit Access." 
3️⃣ Uncheck the email address checkbox. 
4️⃣ Click Continue.

Here are some scenarios of account takeovers I've reported based on different target app behaviors:

Account Takeover via Linking Facebook Flow: 
1️⃣ Went to http://example[.]com, used "Login with Facebook" (Uncheck share email on Facebook).

2️⃣ The target site asked to enter an email to link my FB account as no email was shared from FB. Entered victim@example.com, a confirmation link was sent to the victim's email to bind the account.  

3️⃣ Repeated the same steps on the target site using the same FB account, this time choose to link attacker@example.com on target site – received the same link as step (2) on the attacker controlled email!  

4️⃣ Knowing this, repeated the same steps again to link victim@example.com, and used earlier link which was received on attacker@example.com to takeover victim@example.com account.

Direct Account Takeover via Login with Facebook: 
1️⃣ Went to http://example[.]com, used "Login with Facebook" (Uncheck share email on Facebook).

2️⃣ The target site prompted me to enter an email to link the FB account to an existing account since no email was shared from FB. Entered victim@example.com. It directly logged me into victim@example.com without any further verification, leading to a complete account takeover.

Pre-Account Takeovers: 
Do you have a target app that heavily relies on a user's email domain to grant access to organizations or critical features based on whitelisted domains? Using this technique can help you bypass email verification requirements, allowing you to claim any email. Consequently, you may be able to access critical features of other organizations permitted for emails with the same domain.