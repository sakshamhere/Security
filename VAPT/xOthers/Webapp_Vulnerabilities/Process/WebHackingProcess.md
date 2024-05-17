Part-1 - RECONNAISSANCE

* Profiling The Infrastructure

# - Server Discovery

> whois                     (Internet Footprinting)

> nslookup                  (DNS Interrogation)

> Ping                      (server discovery by ICMP Echo Requests)

> Nmap, fscan               (Discovery Using Port Scanning)

> lbd                       (Checking for Loadbalancers)

> Service Discovery         (Nmap - figure out what ports are running HTTP (orSSL as the case may be))

> Banner Grabbing           (Nikto, Nmap, netcat, curl, fscan, x-pwered-by header, other)


* Hacking web Servers

> Web Servers               (Apache Server, Microsoft Internet Information Server (IIS), Netscape Enterpise Server)

> Bypassing/Circumventing   (Loadbalancers and Proxy servers)

> Automated Vulnerability Scanning Software (Nikto, Webinspect, AppScan)

> DENIAL OF SERVICE AGAINST WEB SERVERS


* Surveying The web Application

> Docuemting App Structure   

    - Page Name?                    Make note of Page Name
    - Page Path?                    Make note of its Path
    - Directory                     Make note of Directory
    - Require Authentication?       Make note if it Require Authentication
    - Require SSL?                  Make note if it Require SSL
    - GET/POST Arguments?           Make note of arguments passed with request for page
    - Any Comments?                 Make note if there exist any comment on page


> Manually Inspecting        

    - Statically Generated Pages         HTML source may contain comments or information.               
    - Dynamically Generated Pages        (.asp, .jsp, .php, and so on) are more interesting.
    - Directory Structure                Check for Interesting Directories like /admin, /logs and more
    - Robots.txt                         robots.txt file provides an excellent snapshot of the directory structure
    - Helper Files                       check for helper files

            - CSS files
            - XML Style Sheets
            - Javascript Files
            - Include Files              (.inc) often control database access or contain variables used internally by the application
            - others                     References to ASP, PHP, Perl, text, and other files might be inthe HTML source.
        
    - Java Classess and Applets          try tricks to download, If downladable, you can peek inside the code 
    - HTML comments and content          check for information in HTML 
    - Forms  

        - Check for Method used, 
        - scripts called in Action, 
        - Maxlength/input restrictions, 
        - Hidden feilds, 
        - Autocomplete applied?

    - Query Strings

        - User Identification           Look for values that represent the user.
        - Session Identification        Look for values that remain constant for an entire session.
        - Database Queries              Inspect the URL for any values that appear to be passed into a database.
        - Search Queries                search page accepts a string for the user’s query. It may also take hidden fields or hard-coded values 
        - File Access                   Do the argument values appear to be filenames?
        - Others                        try arguments like (debug, dbg, admin, source, show etc)
    
    - Backend Connectivity

        - Note when information is read from or written to the database (such as updating address information or changing the password).
        - Highlight pages or comments within pages that directly relate to a database or other systems.
        - A misconfigured server could allow anyone to upload, delete, modify, or browse the Web document root. Check to see if they are enabled

    - Server Headers

        - The HTTP headers returned by the Web server also reveal the operating system, Web server version, and additional modules.

    - Automate Tools                    Tools like Burp and ZAP can spider the app

