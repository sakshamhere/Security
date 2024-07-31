# Email Verification Bypass

https://x.com/Jayesh25_/status/1725429962931335599?s=20

Identify Features Dependent on Email Domain:
Identify critical features linked to a user's email domain. For instance, consider a target app that grants access to resources based on your email domain. Some apps let you join a team or workspace directly if your email matches the team's domain (e.g., join Victim SITE XYZ only with sample@victimsitexyz[.]com). Others restrict access to documents or videos based on email domain whitelisting. Numerous such opportunities exist where email plays a crucial role.

Here's a simple trick that often works to bypass email verification and claim an unregistered email on any domain:

1️⃣ Log in to your attacker account and change your email address to an attacker-controlled email (e.g., attackeremail@attackerdomain.com). 

2️⃣ You'll likely receive an email confirmation link on your attacker-controlled email (Do not verify it yet). 

3️⃣ Now, change your email to the unregistered email or domain you wish to HIJACK (e.g., victimemail@victimdomain.com). 

4️⃣ This action will send an email verification link to victimemail@victimdomain.com, which you don't have access to. 

5️⃣ Try clicking on the "Email" verification link sent earlier to attackeremail@attackerdomain.com. If the system fails to revoke the previous email verification link, the link for attackeremail@attackerdomain.com could end up verifying the email for victimemail@victimdomain.com, allowing you to claim it as verified.

Once you've claimed an email associated with another organization's domain, identify the associated functions to prove impact and report it to earn some generous bounties!

Numerous similar misconfigurations exist that you can leverage to bypass email verification checks.


# Regsiter victim without his involvement / Account hijacking via invitation flow / Pre-Account Takeover
https://x.com/Jayesh25_/status/1726189011624989125?s=20

Here are the prerequisites that must be met to proceed with these attacks:

1️⃣ Ensure your target app supports inviting team members within the application. 

2️⃣ Verify that your target app allows account signup without email verification, or identify an email verification bypass vulnerability.

Here's my approach to identifying and reporting these issues:

1️⃣ Log in to your account and invite a new team member, e.g., testaccount@example.com (Ensure this account isn't registered on the platform). 

2️⃣ This typically sends an invitation link to testaccount@example.com to sign up and join the team by accepting the invite. 

3️⃣ To test if the target app is vulnerable, disregard the invitation email link and attempt to sign up for an account directly using testaccount@example.com, assuming no email verification is required on the target app or that you've identified an email verification bypass. 

4️⃣ Once logged in to the target app, you'll likely discover an invitation that enables you to accept it on behalf of the victim, granting unauthorized access to the team with the assigned role (e.g., admin, team, etc.), resulting in a significant security impact.

The issue here is that anyone can sign up using an email that hasn't been registered on the platform yet but is awaiting a pending invitation, possibly with an admin role or another role in an organization. 

`Unlike a regular pre-account takeover, this one is far more Impactful as it affects an existing business flow. A person shouldn't have the ability to sign up and claim someone else's in-progress Invite. The consequences are far worse than a pre ato.`

`However, the flow here is that an attacker can collect all emails of an org that uses the service and sign up using all those accounts and hope for an account sitting there that hasn’t accepted an invitation yet.`


Another Scenarios I have encountered is: 
1. Send invite to test@example.com
2. Disregard Invite, directly signup.
3. test@example.com becomes part of the organisation.
4. Victim organisation dashboard still shows that test@example.com hasn’t accepted the invitation sent to email. 
5. But in real time test@example.com remains part of the organisation anonymously.



# invitation link has no expiry
https://x.com/Jayesh25_/status/1726886306460872789?s=20

If you're working on a target that offers user invitations via an invitation link, you might be surprised by how often these simple issues go unnoticed and unreported. In my early days, I reported over 10+ similar issues to programs, earning me quick wins and $$$!

Here's how you can turn this feature into a reportable security issue: 

1️⃣ Generate an invitation link and send it to your secondary account to join the team. 
2️⃣ Accept the invitation. 
3️⃣ Remove the secondary user from the team. 
4️⃣ Try to rejoin the organization using the same invitation link, and prepare to be amazed!

This issue allows an individual to rejoin the organization with the same role, even after removal. If the invitation link has no expiry and is not revoked on removal, it poses a security risk, granting access back to the organization with the same privileges as before.

Low/Medium - It all depends on the product. Think about it this way. A H1 employee that was a triager once was later fired or quit his job. Now what If he can use an outdated Invite link to regain access? The Impact can vary depending on the target app and the underlying functions.