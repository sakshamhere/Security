# Common Gateway Interface (CGI)

https://www.geeksforgeeks.org/common-gateway-interface-cgi/

The Common Gateway Interface (CGI) provides the middleware between WWW servers and external databases and information sources. The World Wide Web Consortium (W3C) defined the Common Gateway Interface (CGI) and also defined how a program interacts with a Hyper Text Transfer Protocol (HTTP) server.

The Web server typically passes the form information to a small application program that processes the data and may send back a confirmation message. This process or convention for passing data back and forth between the server and the application is called the common gateway interface (CGI). 

Features of CGI:

    It is a very well defined and supported standard.
    CGI scripts are generally written in either Perl, C, or maybe just a simple shell script.
    CGI is a technology that interfaces with HTML.
    CGI is the best method to create a counter because it is currently the quickest
    CGI standard is generally the most compatible with today’s browsers


    Note:
The cgi library was a Python library that provided a simple interface for writing CGI scripts (scripts that run on a web server). 
This library has been deprecated in favor of more modern and feature-rich alternatives, such as the web framework Django.


CGI runs bash as their default request handler and this attack does not require any authentication that’s why most of the attack is taken place on CGI pages to exploit this vulnerability.

# CGI-Bin
https://www.techopedia.com/definition/5585/cgi-bin#:~:text=A%20CGI%2Dbin%20is%20a,of%20scripts%20in%20Web%20design.


A CGI-bin is a folder used to house scripts that will interact with a Web browser to provide functionality for a Web page or website. Common Gateway Interface (CGI) is a resource for accommodating the use of scripts in Web design. As scripts are sent from a server to a Web browser, the CGI-bin is often referenced in a url.

https://www.youtube.com/watch?v=ecKNxataqVw