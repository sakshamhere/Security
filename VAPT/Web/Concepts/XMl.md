# What is XML?  https://www.youtube.com/watch?v=gjm6VHZa_8s
XML is markup language similar to HTML, the diffrence is HMTL is about data representation and XML is more about data transportation and storage

XML is used in APIs, UI layout and styles, configs, etc

* Entities      https://www.w3resource.com/xml/entities.php

- Entities are like variable for XML, you can assign a value to it and use it in multiple parts in a document

* DTD

- These entitnes are defined in a seperate part of XML document called DTD (Document Type Definition)

- An entity is created inside a Doctype which basically tells XML parser that this is DTD

Entities can not only store value that we specify, but they can also pull value from a local file, or even fetch the data over a remote network and store them as entities, This opens a wide range of attack surface

There are 3 types of entities - General, Parameter and Predefined

1. Genral - where in we refrence a DTD defined value somewhere else

2. Patameter - these are only allowed in DTD, for example creating an entity whose value is another entity, this can only be refer in DTD

A parameter entity must be declared with a preceding percent sign (%) with a white space before and after the percent sign, and it must be referenced by a percent sing with no trailing white space. A typical parameter entity declaration looks like this: <!ENTITY % myParameterEntity "myElement">

3. Predefined  - these are predefined and have not to be defined in DTD, these are useful when we want to use special character in XML, as we cant use <*&^> etc direclty as XML parser will give error

Example XML 

<?xml version="1.0">
<!DOCTYPE XXE [
    <!ENTITY myentity SYSTEM "file:///etc/passwd">
]>
<Display>&myentity;<Display/>

In the above example we can see entity "myentity" is being defined and is used in Display tag, we see the SYSTEM attribure in ENTITY definition. 

The SYSTEM is used to inform parser that the entity is of external type and to fetch the content from external source specified and store in entity

We can also spefiy another DTD to refer instead of some file/url referece for external entity

********************************************************************************************************************************

# XPATH
https://www.w3schools.com/xml/xml_xpath.asp

XPath uses path expressions to select nodes or node-sets in an XML document. These path expressions look very much like the expressions you see when you work with a traditional computer file system.

XPath expressions can be used in JavaScript, Java, XML Schema, PHP, Python, C and C++, and lots of other languages.

# XML HttpRequest
https://www.w3schools.com/xml/xml_http.asp

All modern browsers have a built-in XMLHttpRequest object to request data from a server.
The XMLHttpRequest Object

The XMLHttpRequest object can be used to request data from a web server.

The XMLHttpRequest object is a developers dream, because you can:

    Update a web page without reloading the page
    Request data from a server - after the page has loaded
    Receive data from a server  - after the page has loaded
    Send data to a server - in the background

Example
var xhttp = new XMLHttpRequest();
xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
       // Typical action to be performed when the document is ready:
       document.getElementById("demo").innerHTML = xhttp.responseText;
    }
};
xhttp.open("GET", "filename", true);
xhttp.send();

# XML Parser