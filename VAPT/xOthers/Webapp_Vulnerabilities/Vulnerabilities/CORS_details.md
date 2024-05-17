https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request


`For HTTP request methods that can cause side-effects on server data (in particular, HTTP methods other than GET, or POST), the specification mandates that browsers sends a "preflight" request with the HTTP OPTIONS request method, and then, upon "approval" from the server, sending the actual request. `

Servers can also inform clients whether "credentials" (such as Cookies and HTTP Authentication) should be sent with requests.

# CORS Preflight request

A CORS preflight request is a CORS request that checks to see if the CORS protocol is understood and a server is aware using specific methods and headers.

It is an OPTIONS request, using three HTTP request headers: Access-Control-Request-Method, Access-Control-Request-Headers, and the Origin header.


OPTIONS /resource/foo
Access-Control-Request-Method: DELETE
Access-Control-Request-Headers: origin, x-requested-with
Origin: https://foo.bar.org


If the server allows it, then it will respond to the preflight request with an Access-Control-Allow-Methods response header, which lists DELETE:

HTTP/1.1 204 No Content
Connection: keep-alive
Access-Control-Allow-Origin: https://foo.bar.org
Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE
Access-Control-Max-Age: 86400

*********************************************************************************************************************

For security reasons, browsers restrict cross-origin HTTP requests initiated from scripts. For example, `XMLHttpRequest` and the `Fetch` API follow the same-origin policy.

This means that a web application using those APIs can only request resources from the same origin the application was loaded from unless the response from other origins includes the right CORS headers.