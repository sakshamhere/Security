https://x.com/Jayesh25_/status/1722597769385329062?s=20

Here are the common issues you should be on the lookout for:

# 1️⃣ Token and username parameter: 
Some target apps often generate a password reset link containing a token and a username parameter. In such cases, request a password reset link on your attacker account, navigate to it, and attempt to replace the "username" parameter with the victim's username. Try resetting the password using your token. This is frequently one of the most common issues I've encountered that leads to an Account Takeover (ATO).

# 2️⃣ Password reset poisoning: 
Request a password reset using the victim's account and alter the "Host" header of the request to https://attackercontrolledsite(.)com. If the target app is vulnerable, this will trigger an email to the victim with a password link pointing to your server (e.g., https://attackercontrolledsite(.)com?token=dsksdjsdjsdjdsjdsjsd. When the victim clicks on this link, you will receive the password reset token, paving the way for an ATO.

# 3️⃣ HTTP Parameter Pollution: 
When requesting a password reset, always attempt to pass multiple email parameters (e.g., email=victim@target(.)com&email=attacker@target(.)com). Depending on how the application's backend is set up, it may have different routines running on various servers to check validity and send emails. Consequently, it could inadvertently send the password reset link of victim@target(.)com to attacker@target(.)com.



# Rate limiting
https://x.com/Jayesh25_/status/1720517990028923146?s=20

Have you encountered a login page or a forgot password page with OTP where rate limits have been introduced? 🕵️‍♂️

Here's how you can bypass some of these implementations:

# 1️⃣ 🕵️‍♀️ Google Captchas implemented? 
No worries, always try removing the captcha parameter or replace it with null and send the request without the captcha. Sometimes a fallback method allows you to get past the captcha requirement, making it vulnerable to a lack of rate limiting.

# 2️⃣ 🌐 IP restricted? 
Check if your IP was blocked and attempt to make a request using a different IP. If that works, you're in luck! You can usually bypass these limitations through IP rotation. Services like Brightproxy or Burp Suite IP rotate extension can assign a new IP address with every request.

# 3️⃣ 🤖 If nothing works, try appending %0d or %0d before the username (e.g., %0dvictim@target.com). 
This can sometimes trick the server into checking if %0dvictim@target.com is locked. If not, while processing the login attempt, it strips the %0d and makes an attempt for victim@target.com. It's possible that %0dvictim@target.com may be blocked too after 5 attempts. In that case, keep appending an additional %0d after every 5 attempts (e.g., %0d%0dvictim@target.com and vice versa).

# 4️⃣ 🤯 Rate limit properly implemented? 
Always look for an alternative login or forgot password endpoint. This could be on one of the target's mobile apps or a legacy endpoint in the JS file.

- If reset functionality sends an OTP to user, rate limiting can be tested

- sometimes username enumeration is also possible if no rate limiting is there



# Bypass Account lockout and exploit rate limiting
https://x.com/Jayesh25_/status/1724367910984958113?s=20

In a target app supporting login only with a phone from one specific country, the requests were made with the country code extension in the request body. This immediately prompted me to tinker with the request to see if there was anything unusual about how this was being interpreted at the backend. It looks like I was able to change the country code in the request body to bypass the account lockout limit and still get logged in to the same account.

Here's how I approached this issue:

1️⃣ Navigated to the target app and entered a phone number to log in. An OTP was sent to the phone.

2️⃣ Intercepted the request and noticed two request body parameters: Phone and CountryCode.

3️⃣ Changed the "CountryCode" from +971 to +1, kept the same phone number, and entered the correct "OTP," and it logged me into my account with +971 country code.

4️⃣ This seemed a bit unusual, as it demonstrated that something was wrong since the country code was not being factored or was being stripped off while actually logging someone into an account. But it sort of made sense because the app supported only one country phone number. But then why add the country code to the request if it's not being used at all?

5️⃣ Came up with some creative ideas and said to myself, "Let's try brute-forcing the 4-digit OTP." Looks like the limit was set to 5 attempts after which the account would get locked out.

6️⃣ Came up with another wild imagination: What if the country code was somehow incorrectly being used here to determine what identifier to lockout?

7️⃣ Figured out that I could change the country code to +971, +1, +91, etc., while keeping the same phone number and brute force the OTP, and it never locked my account. This is possibly because there was a design flaw where they were checking for multiple failed attempts with both +[country code][phone#], something like that, while the country code was stripped off for actually validating the OTP with the phone number and during login, as we learned earlier.

End result? This allowed me to circumvent the account lockout limits and take over any user's account by guessing the 4-digit OTP.