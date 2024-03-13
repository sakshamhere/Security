https://x.com/Jayesh25_/status/1727618460979486776?s=20

Here's how I successfully elevated my role to an Internal admin, exposing admin functionalities, resulting in a mass PII leak and access to other sensitive Internal reports:

1️⃣ Navigated to target[.]com and accessed the sign-up page to create an account. 

2️⃣ The sign-up page accepted three parameters: name, email address, and password. 

3️⃣ As a practice, I closely monitored responses from critical functions to spot anything intriguing. Upon successful registration, here's the server's response: 

{"success": true, "user_id": 123, "name": "xxx", "email": "xxx@example.com", "isAdmin": false} 

4️⃣ What would you do if you saw a response like that? You guessed it right! 

5️⃣ Returned to the sign-up form, registered for a new account, and intercepted the following request during sign-up: 

{"name": "xxx", "email": "xxx@example.com", "password": "pass"} 

6️⃣ Injected an additional parameter, "isAdmin": true, to test if the application would process it. Modified my request body to :

{"name": "xxx", "email": "xxx@example.com", "password": "pass", "isAdmin": true} 

7️⃣ BAM! The server processed my account as an admin, making me an Internal admin and revealing significant administrative functionality.