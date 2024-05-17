https://owasp.org/www-community/attacks/Cross_Frame_Scripting
https://www.acunetix.com/blog/web-security-zone/cross-frame-scripting-xfs/


Cross-Frame Scripting (XFS) is an attack that combines malicious JavaScript with an iframe that loads a legitimate page in an effort to steal data from an unsuspecting user. This attack is usually only successful when combined with social engineering. 

An example would consist of an attacker convincing the user to navigate to a web page the attacker controls. The attacker’s page then loads malicious JavaScript and an HTML iframe pointing to a legitimate site. Once the user enters credentials into the legitimate site within the iframe, the malicious JavaScript steals the keystrokes.

# Conditions of a Cross-Frame Scripting Attack

The goal of an XFS attack is to steal user credentials for a certain website or web application. For this to happen, all the following conditions must be met:

    The website or web application must be vulnerable to XFS attacks and must control valuable user input (login data or other sensitive information).
    The attacker must place malicious JavaScript code on a web page that they control.
    The attacker must use social engineering (e.g. a phishing attack) to trick the victim to visit the web page that the attacker controls.
    The victim must use a vulnerable browser version (for example, IE6 on Windows XP)

It is very unlikely that all these conditions are met at the same time, especially since only old browser versions are vulnerable to such attacks. Therefore, an XFS attack is rather unlikely or must be specifically targetted, for example, at an organization that still uses old browsers and operating systems