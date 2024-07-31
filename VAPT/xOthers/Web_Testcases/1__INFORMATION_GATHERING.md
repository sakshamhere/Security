# 1. REVIEW WEBSERVER META FILES FOR INFORMATION LEAKAGE

- Analyze robots.txt and identify <META> tags from website

# 2. REVIEW WEBPAGE CONTENT FOR INFORMATION LEAKAGE

- Find sensitive information from webpage comments and metadata on source code

# 3. IDENTIFY APPLICATION ENTRYPOINTS

- Identify hidden fields, parameters, methods HTTP header analysis

# 4. MAP EXECUTION PATH THROUGH APPLICATION

- Map the application and understand workflows

# 5. MAP APPLICATION ARCHITECTURE

- Identify application architecture including Web language, WAF, Reverse proxy, Application server, Backend Database

Tools used 
# Wget
# Curl

***************************************************************************************************************************************************

# 1. REVIEW WEBSERVER META FILES FOR INFORMATION LEAKAGE

https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage

Test Objectives

    Identify hidden or obfuscated paths and functionality through the analysis of metadata files.
    Extract and map other information that could lead to better understanding of the systems at hand.


# Robots.txt

It is a file which tells web crawlers what not need to be crawled

- curl -O -Ss http://www.google.com/robots.txt && head -n5 robots.txt

# Sitemaps

A sitemap is a file where a developer or organization can provide information about the pages, videos, and other files offered by the site or application,

- wget --no-verbose https://www.google.com/sitemap.xml && head -n8 sitemap.xml

# Security TXT

security.txt is a proposed standard which allows websites to define security policies and contact details.

The file may be present either in the root of the webserver or in the .well-known/ directory. Ex:

    https://example.com/security.txt
    https://example.com/.well-known/security.txt

- wget --no-verbose https://www.linkedin.com/.well-known/security.txt && cat security.txt

# Humans TXT

humans.txt is an initiative for knowing the people behind a website

- wget --no-verbose  https://www.google.com/humans.txt && cat humans.txt

2020-05-07 12:57:52 URL:https://www.google.com/humans.txt [286/286] -> "humans.txt" [1]
Google is built by a large team of engineers, designers, researchers, robots, and others in many different sites across the globe. It is updated continuously, and built with more tools and technologies than we can shake a stick at. If you'd like to help us out, see careers.google.com.


# 2. REVIEW WEBPAGE CONTENT FOR INFORMATION LEAKAGE

https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage

Test Objectives

    Review webpage comments and metadata to find any information leakage.
    Gather JavaScript files and review the JS code to better understand the application and to find any information leakage.
    Identify if source map files or other front-end debug files exist.


# 3. IDENTIFY APPLICATION ENTRYPOINTS

# 4. MAP EXECUTION PATH THROUGH APPLICATION

# 5. MAP APPLICATION ARCHITECTURE

