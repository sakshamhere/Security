https://www.cgisecurity.com/whitehat-mirror/WH-WhitePaper_XST_ebook.pdf

# Background information

`TRACE`

The http `trace` request (containing request line, headers, post data), sent to a trace supporting web server, will respond to the client with the information contained in therequest. 

`Trace` provides any easy to way to tell what an http client is sending and what the server is receiving. 

Apache, IIS, and iPlanet all support trace as defined by the HTTP/1.1 RFC and is currently enabled by default.


`HttpOnly`

httpOnly is a HTTP Cookie option used to inform the browser (IE 6 only until other browsers support httpOnly) not to allow scripting languages (JavaScript, VBScript, etc.) access to the “document.cookie” object (normal XSS attack target)


# The Cross Site Tracing

Basically Cross Site Tracing attack is to bypass httponly control which  does not allow document.cookie to be accessd by javascript.

# How

So the Trace method simply echos the request and response , this include cookie and web authentication strings since they are just headers.

Results of the TRACE request response from the server containes cookie that is not accessible by “document.cookie” hence bypassed the security control.

# Remediation

General Recommendations

1. Sufficiently patch all web browsers against known domain restriction bypass flaws. is
is a more important part of security policy now more than ever.
2. Disable or disallow the TRACE Request method on production and development (unless
needed) web servers.
3. Web server vendors should update their web server packages to disable TRACE by
default.
4. Web server vendors should inform their users on how to disable or disallow TRACE on
existing web servers.