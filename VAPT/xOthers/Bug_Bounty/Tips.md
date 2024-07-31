
1. Whenever I start testing a Web Application i usually start it from the `/settings` page, Because that page contains basic functionality of the application.

- Email change functionality, i noticed that there is no “Current Password Protection”. No current password protection in sensitive action considered as p4 vulnerability in “bugcrowd” platform



CSRF
- Bypass Header token 
    - check it by removing if its validated

- Reusable CSRF token
    - this generally happens in request based tokens, the token can be resued for that user, to exploit we must eb able to get token before logging as shown in this - https://yasserali.com/hacking-paypal-accounts-with-one-click/
    
- Bypass Reference header check
    

- Bypass Origin header check 
    - Sometimes CSRF dosent work and will give erro like 403, becuase your origin header is bening validated, this is similar to having reference header check, hoever sometimes request is accepted if we remove the header
    - Bypass - https://infosecwriteups.com/story-of-a-weird-csrf-bug-bde1129c106e
    - When I tried to follow this, it worked. The request was sent without the Origin header. But it was only working when I used the Form method inside an iframe with data protocol, the Origin header would always be sent in case of fetch and other similar related methods.






JSON CSRF 
- sometimes POC dosend work because it adds extra "=" in end automatically
    for example in POC post data we are trying to send - {“email”:”attacker@Hacker.com”}
    but its actully going - {“email”:”attacker@Hacker.com”}=
    How to dealt with “=” it ? quite simple, i used one extra parameter in my post data that is ignore. Ignore simply takes “=” and ignores it :)

    Final Exploit:

    <html>
    <form action=”https://famebit.com/auth/changeEmail" method=”POST” />
    <input type=”hidden” name=”&#123;&quot;email&quot;&#58;&quot;Attacker@hacker.com&quot;&#44;&quot;ignore&quot;&#58;&quot;” value=”&quot;&#125;” />
    <input type=”submit” value=”Submit Request”>
    </form>
    </html>

    POST Data:

    {“email”:”attacker@hacker.com”,”ignore”:”=”}


Multipart form CSRF
    - https://infosecwriteups.com/story-of-a-weird-csrf-bug-bde1129c106e
    - csrf poc without user interaction -File upload trick - this trick allows me to upload any fake document without depending on the victim to upload any file
        - https://infosecwriteups.com/story-of-a-weird-csrf-bug-bde1129c106e
        - https://youtu.be/J2icGMocQds

File Upload CSRF 
    -  http://aetherlab.net/2013/04/here-it-is-the-file-upload-csrf/?source=post_page-----bde1129c106e--------------------------------
    - csrf poc without user interaction - File upload trick - this trick allows me to upload any fake document without depending on the victim to upload any file
        - https://infosecwriteups.com/story-of-a-weird-csrf-bug-bde1129c106e
        - https://youtu.be/J2icGMocQds