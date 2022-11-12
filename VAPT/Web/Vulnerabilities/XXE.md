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

# What is XXE?

XML external Entity attack is a type of attack that occours when XML input containing a reference to an external entity is processes by weakly configured XML parser.

# Impact of EEX

This attack may lead to disclousure of confidential data, DOS, SSRF, port scanning from the macchine where parser is located.

# Example 

Exploiting XXE to retrieve files

For example, suppose a shopping application checks for the stock level of a product by submitting the following XML to the server:

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck>

The application performs no particular defenses against XXE attacks, so you can exploit the XXE vulnerability to retrieve the /etc/passwd file by submitting the following XXE payload:

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>

This XXE payload defines an external entity &xxe; whose value is the contents of the /etc/passwd file and uses the entity within the productId value. This causes the application's response to include the contents of the file:

Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin

# Attacks performed by XXE?   https://portswigger.net/web-security/xxe


* Exploiting XXE to retrive files - where an external entity is defined containing the contents of a file, and returned in the 
                                    application's response.

* Exploiting XXE to perform SSRF attacks - Aside from retrieval of sensitive data, the other main impact of XXE attacks is that they 
                                           can be used to perform server-side request forgery (SSRF). This is a potentially serious vulnerability in which the server-side application can be induced to make HTTP requests to any URL that the server can access.

* Exploiting blind XXE exfiltrate data out-of-band -  where sensitive data is transmitted from the application server to a system that 
                                                      the attacker controls

                                                      Blind SSRF vulnerabilities arise when an application can be induced to issue a back-end HTTP request to a supplied URL, but the response from the back-end request is not returned in the application's front-end response.

                                                      The most reliable way to detect blind SSRF vulnerabilities is using out-of-band (OAST) techniques. This involves attempting to trigger an HTTP request to an external system that you control, and monitoring for network interactions with that system.

                                                      The easiest and most effective way to use out-of-band techniques is using Burp Collaborator. You can use the Burp Collaborator client to generate unique domain names, send these in payloads to the application, and monitor for any interaction with those domains. If an incoming HTTP request is observed coming from the application, then it is vulnerable to SSRF.


* Exploiting blind XXE to retrieve data via error messages - An alternative approach to exploiting blind XXE is to trigger an XML 
                                                             parsing error where the error message contains the sensitive data that you wish to retrieve. This will be effective if the application returns the resulting error message within its response.

# Hidden attack surface for XXE injection

Attack surface for XXE injection vulnerabilities is obvious in many cases, because the application's normal HTTP traffic includes requests that contain data in XML format. 

In other cases, the attack surface is less visible. However, if you look in the right places, you will find XXE attack surface in requests that do not contain any XML.

* XInclude Attacks

Some applications receive client-submitted data, embed it on the server-side into an XML document, and then parse the document.In this situation, you cannot carry out a classic XXE attack, because you don't control the entire XML document and so cannot define or modify a DOCTYPE element.

To perform an XInclude attack, you need to reference the XInclude namespace and provide the path to the file that you wish to include. For example:

<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>

* XXE attacks via file upload

Some applications allow users to upload files which are then processed server-side. Some common file formats use XML or contain XML subcomponents.

For example, an application might allow users to upload images, and process or validate these on the server after they are uploaded. Even if the application expects to receive a format like PNG or JPEG, the image processing library that is being used might support SVG images. 

Since the SVG format uses XML, an attacker can submit a malicious SVG image and so reach hidden attack surface for XXE vulnerabilities.


* XXE attacks via modified content type

Most POST requests use a default content type that is generated by HTML forms, such as application/x-www-form-urlencoded. Some web sites expect to receive requests in this format but will tolerate other content types, including XML.

For example, if a normal request contains the following:


Content-Type: application/x-www-form-urlencoded

Then you might be able submit the following request, with the same result:

Content-Type: text/xml
<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>

If the application tolerates requests containing XML in the message body, and parses the body content as XML, then you can reach the hidden XXE attack surface simply by reformatting requests to use the XML format.


# Test for XXE

* Discovery / Detection Technique

    The first step in order to test an application for the presence of a XML Injection vulnerability consists of trying to insert XML metacharacters.

    - Single quote: ', Double quote ", Angular parentheses: > and <, Comment tag: <!--/-->, Ampersand: & - When not sanitized, this character could throw an exception during XML parsing, if the injected value is going to be part of an attribute value in a tag.

    - Tag Injection

    Once the first step is accomplished, the tester will have some information about the structure of the XML document. Then, it is possible to try to inject XML data and tags

    - Source Code Review

    Check source code if the docType, external DTD, and external parameter entities are set as forbidden uses.

* Automated testing

The vast majority of XXE vulnerabilities can be found quickly and reliably using Burp Suite's web vulnerability scanner.

* Manual testing

- Testing for file retrieval by defining an external entity based on a well-known operating system file and using that entity in data that is returned in the application's response.

- Testing for blind XXE vulnerabilities by defining an external entity based on a URL to a system that you control, and monitoring for interactions with that system. Burp Collaborator client is perfect for this purpose.

- Testing for vulnerable inclusion of user-supplied non-XML data within a server-side XML document by using an XInclude attack to try to retrieve a well-known operating system file.


# Prevention

* Generally, it is sufficient to disable resolution of external entities 

* Virtually all XXE vulnerabilities arise because the application's XML parsing library supports potentially dangerous XML features that the application does not need or intend to use. The easiest and most effective way to prevent XXE attacks is to disable those features.

* The safest way to prevent XXE is to diable DTD completely, disabling DTD makes the parser secure against DOS.

* If its not possible to disable completely then external entities and DTDs must be disabled in such a way that's specific to parser.