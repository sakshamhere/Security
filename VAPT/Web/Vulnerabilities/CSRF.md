https://www.youtube.com/watch?v=7bTNMSqCMI0

# what is Session 

user logs in banking application, user supplies his credentials to web app/server the app then sets a cookie in users browser, this cookie identifies user for future requests

anytime in future request the browser checks for cookie for so n so domain, if it founds it sets it then at server backend it is checked which user is assigned this cookie, the app checks the permission for reource the user is trying to access if he has then resource is presented to user

# What is CSRF? 

CSRF is an attack where the attacker causes the victim user to carry out and action unintentionally while the victim is authenticated

 - the victim needs to be already authenicated or looged in

# Whar attacker want to do?

Step 1 - sending user a malicious link that will conduct a CSRF attack

- for example the link https://bank.com/attack/change?email=attack@gmail.com  changes the email address of the user, 

- all what link does is that it chnages the email add of attacker from one to another

- However if attacker successfuly gets victim to click on this link while is logged in, the attacker will be able to change victim emial to his email

- when victims clicks the link the session cookie get sets with link, backed then gets to know that user wants to change the email address

- since the attacker now already changed email to his, he can now use the forgot password and reset password and compromise the account

# How attacker do it?

So the attacker dosent send a link dorectly with the bank domain with information of changing password in it as victim can easily understand it

Instead the attacker will create a malicious website that interest victim, while the victim looks this website there is a script executing in backgound  as soon page loads in a invisible <iframe> which user cant see and it changes the email address on victims behalf

# Conditions required for CSRF attack

* A relevant action - an action that causes harm to user (like changing email as in above)

* Cookie based session handeling - the application has to be using cookies for the session management

* No unpredictable request parameters - there should be no unpredictable paramenters like CSRF token

* Existence of HTML tags whose presence cause immediate access to an HTTP[S] resource; for example the image tag img.

# Impact of CSRF

It depends on the relavant action as in example above for email the impact on CIA will be high, but if you explointing a functionalty which simply changes text of website and dosent qualify to be a relavent action the impact on CIA will be none/low

# Testing for CSRF

- Audit the application for session management - If session management relies only on client side values (information available to the 
                                                 browser), then the application is vulnerable

Black box perspective

- Review all the key functionalities in application
- identify all application functions that satisfy the 3 conditions for CSRF
- Create a Poc script to explot CSRF, to show the function is vulberable
    Get request: <img> tag with src attribute set to vulnerable URL
    POST request: form with hidden fields for all the required parameters and target set to vulnerable URL

White box perspective

- Identify framework looking at source code as modern framewors have built in defences
- find out how this framework defend CSRF
- review code to ensure the defences are not disabled, sometime developers does them which leads to attack vector
- review all sensitive functionality to ensure CSRF defence has been applied




# How to Defend against CSRF

* Primary Defences - that we should definitly apply

- Use of CSRF Token

How should CSRF be generated, used and validated?

1. It should be generated on server side not on client side
1. It should be a long unpredictable string with high entropy
2. It should be tied to user's session 
3. It has to be validated regardless of being POST or GET request as some appliocation allows to change post request to get request
4. If token is not submitted request should be rejected and logged as it can be possible attack

How should CSRF tokens be transmited?

1. It should be in hidden feild of an HTML form submitted using POST method, when user submits it gets passed on with request
2. using custom request header (this is very less commonly used)

-- less secure way

3. Tokens should not be submitted in query parameters in URL, 
- because anyone can see them in url
- urls are loggend in backend and will be filled with users CSRF
- urls are transmitted as part of refferer header, so any third pary application you visit after being looged in to application can potentially gain access to your CSRF

4. Never submit CSRF tokens as/within cookes, as attacker then no need to find it as it will automatically get attached in logged session request of attacker


* Addtional Defences - that we can apply in addition to primary defences

- Use of SameSite cookies

SameSite attribute can be used to control whether cookies are submitted in cross-site request.

samesite attribute is addedd to cookie response header which can be given three values (STRICT, LAX, NONE)

STRICT - the cookies will not be sent with the request for third-party websites (not prefreed as impairs user experiance )

LAX - allows only to sent when 
1. the request is sent in GET method
2. the request is from top level navigation like clicking a link, so a sript automatically getting executed wont be allowed to get cokkies with it

NONE = equvalent as not having samesite attribute

* Inadeuate Defences - the one which can be bypassed

- Use of Referer header

Referer header - The Referer HTTP request header contains an absolute or partial address of making the request.

The way application defends using it is that is they check referer header is equal to domain of application, if its equal then request valid.

This is inadequarte because 
 - Referer header can be Spoofed
 - the defence can be bypassed 
    (if its not present the app dosent check for it and accepts request)
    (the referrer header is only checked to see if it contains the domain and exact mactch is not made)


