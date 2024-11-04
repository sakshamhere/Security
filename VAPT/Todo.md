
Priority 

One New Technique of exploiting vulnerability per day (check HACTIVITY)

One HTB Analysis per day 

Some AD Boxes to be analysed

Forest
Active
Reel
Mantis
Blackfield
Monteverde
Search

Offshore

Read one AD Pentest Blog per day

One New Vulnerability Read per day (check everyday for updates)






Authorization Bypass

Access resource without authentication
Access resource after session termination
Access privileged resource with authentication
Forced Browsing
Inspecting & Manipulating HTML 
Unrestricted HTTP methods
HTTP Response parameter pollution
Manipulating Request Headers
Insecure Direct Object Reference
Mass Assignment 
Supporting non-standard Request Headers
Server-side parameter pollution 


Access resource without authentication
At times resources might be accessible directly due to improper or incomplete implementation of authentication requirements by web app.

Access resource after session termination
At times resources are still accessible after logout due to improper session termination.

Forced Browsing
At times restricted or privileged web pages can be directly accessed by requesting complete URL in the user's session, In worse case this is not limited to data exposure it might also allow access to privileged functions of that web page.

Inspecting & Manipulating HTML
At times developers implement the user’s authorization on UI level, this can be easily bypassed by manipulating javascript and CSS of rendered HTML after using browser tools inspection,, after manipulation successful request allows access to privileged functions.

HTTP Response parameter pollution
At times the developer implements user’s authorisation on UI level, this UI functions depend on HTTP response parameters, in such scenarios intercepting and manipulating such parameters may allow access to admin or privileged functions.
Manipulating Request Headers
At times request headers like content-type can be manipulated to access restricted or privileged content type responses..

Insecure Direct Object Reference
At times applications access resources using unique ids with respect to authenticated users, manipulation of these id may allow access to resources that belong to different users.

Mass Assignment
At times authorization in API request parameters automatically binds to hidden internal objects, attacker may guess and add these hidden parameters or modify existing parameters in a way to access internal privileged resources.

Supporting non-standard Headers
At times web app might support non-standard headers (X-Original-URL, X-Rewrite-URL, X-Forwarded-For, X-Forward-For, X-Remote-IP, X-Originating-IP, X-Remote-Addr, X-Client-IP etc), injecting these headers may allow access to internal privileged resources.

Server-side parameter pollution
At times attackers may be able to manipulate or inject parameters, which may enable them to Override existing parameters, Modify the application behaviour or Access unauthorised data.

Remediations & Best Practises
Implement authentication requirements for all resources.
Implement proper session termination.
Restrict unprivileged users to access privileged web pages with proper error handling.
Never implement authorisation segregation on UI level, instead validate it on backend code.
Implement proper authorization checks for object references at the backend.
Implement authorization checks for all API request parameters.
Implement an allowlist of permitted HTTP methods.
Validate that the content type is expected for each request or response.


Parameter Pollution
