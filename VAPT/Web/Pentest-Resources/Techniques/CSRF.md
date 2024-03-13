https://x.com/Jayesh25_/status/1719383263511212225?s=20

# 1️⃣ Swap "POST" with "GET": 
Instead of using POST requests, switch to GET and move the body parameters into the URI. This simple maneuver often overrides CSRF token implementations, enabling a full-blown CSRF attack.

# 2️⃣ JSON Requests: 
Even JSON requests relying on cookies can be vulnerable to CSRF. Here's the trick: send your request with a content-type of text/html and format the body in JSON. In some cases, if the application doesn't rely on the content-type header, CSRF can still work its magic.

# 3️⃣ Don't Blindly Trust CSRF Tokens: 
Just because an application has a CSRF token doesn't mean it's foolproof. Sometimes, backend validation for these tokens can be flawed. This means that even with the same token, a CSRF attack may still work on other users' accounts.

# 4️⃣ Remove the CSRF Token Parameter:
Believe it or not, some applications are designed to support legacy versions. If you try removing the CSRF token parameter from the request, it may still work. This is often because apps have dual implementations, and if the parameter is missing, they fall back to the legacy version to support older versions of the app, which can often be vulnerable.

# 5️⃣ Legacy Endpoints: 
Hidden in JS files are legacy endpoints that may no longer be actively in use, but they can still be functional and vulnerable to CSRF attacks. These abandoned endpoints are usually not maintained or updated to the latest security standards, making them prime targets for CSRF exploitation.