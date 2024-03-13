# Web Services Description Language (WSDL)
https://www.ibm.com/docs/en/radfws/9.6?topic=SSRTLW_9.6.0/org.eclipse.jst.ws.doc.user/concepts/cwsdl.htm
https://www.youtube.com/watch?v=MUq_RkG7De0

WSDL stands for Web Services Description Language. It is the standard format for describing a web service. WSDL was developed jointly by Microsoft and IBM.
Features of WSDL

- WSDL is an XML-based protocol for information exchange in decentralized and distributed environments.

- WSDL definitions describe how to access a web service and what operations it will perform.

- WSDL is a language for describing how to interface with XML-based services.

- WSDL is an integral part of Universal Description, Discovery, and Integration (UDDI), an XML-based worldwide business registry.

- WSDL is the language that UDDI uses.

- WSDL is pronounced as 'wiz-dull' and spelled out as 'W-S-D-L'.




# SOAP
https://www.guru99.com/soap-simple-object-access-protocol.html

In today’s world, there is huge number of applications which are built on different programming languages. For example, there could be a web application designed in Java, another in .Net and another in PHP.

Exchanging data between applications is crucial in today’s networked world. But data exchange between these heterogeneous applications would be complex. So will be the complexity of the code to accomplish this data exchange.

One of the methods used to combat this complexity is to use XML (Extensible Markup Language) as the intermediate language for exchanging data between applications.
Every programming language can understand the XML markup language. Hence, XML was used as the underlying medium for data exchange.

But there are no standard specifications on use of XML across all programming languages for data exchange. That is where SOAP software comes in.

SOAP was designed to work with XML over HTTP and have some sort of specification which could be used across all applications. 

SOAP is an XML-based protocol for accessing web services over HTTP. It has some specification which could be used across all applications.


# Key Differences between SOAP and WSDL

Both are popular choices in the market; let us discuss some of the major Difference:

- SOAP (Simple Object Access Protocol) is basically the XML based messaging protocol specification that is used for exchanging distinct and structured information in the implementation of web services in computer networks, whereas WSDL (Web Services Description Language) is an XML-based interface definition language for defining different web service functionalities.

- SOAP is a favourable choice from the extensibility perspective than WSDL, and it provides different layers of security and related extension support.

- In the case of SOAP, it provides support for all or most of the programming models, but this is not the case with WSDL files.

- There is also a lot of community support for SOAP and its users, whereas WSDL also provides a large range of community and paid support. Normally all the WSDL versions use to provide long-term customer support.

- WSDL is more preferred than SOAP from the performance perspective as it may be a little bit slower sometime due to the fundamental actualization and binding processes.

- WSDL explains the framework patterns for the webserver communication and internet message transfer process more closely and clearly than SOAP.

- SOAP has the encryption capability for messages and restricted view filter process, but this is not much smoother and easily handled in the case of WSDL.

- SOAP provides different layers of security patches towards its related supports and appears to be more secure than WSDL security handling.

- SOAP has four layers of architecture like Header, Body, Envelope, and Fault, whereas, in the case of WSDL architecture, it has three main elements for the same like Types, Binding, and Operations.