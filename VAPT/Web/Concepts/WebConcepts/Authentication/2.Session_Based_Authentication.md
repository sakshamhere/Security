# Form Based / Session based Authentication

* Forms-based authentication does not rely on features supported by the basic Web protocols like HTTP and SSL (such as Basic auth or client-side certifications).

* It is a highly customizable authentication mechanism that uses a form, usually composed of HTML with <FORM> and <INPUT> tags delineating fields for users to input their username/password information. After the data is input via HTTP (or SSL), it is evaluated by some server-side logic and, if the credentials are valid, some sort of token is given to the client browser to be reused on subsequent requests. 


* How it works?     

- Client request for form, he/she is presented with form from server the form contains input feild and a hidden field to prevent CSRF

- User enters his details and POSTs to server, unless the SSL is implemented the credentials traverse in cleartext

- The server recieves the data and validates them in databvase, if credentials match it redirects user to requested resource with a set-cookie header with authentication token, this cookie can be set to expire after sometime

- Next time users request someting, it sends the cookie with token and dosent have to authenticate again


* Whats the Problem?

- It's stateful. The server keeps track of each session on the server-side. The session store, used for storing user session information, needs to be shared across multiple services to enable authentication. Because of this, it doesn't work well for RESTful services, since REST is a stateless protocol.

- Cookies are sent with every request, even if it does not require authentication.,

- Cookies can be stolen, manipulated if they are not encrypted

- CSRf attacks can be there


