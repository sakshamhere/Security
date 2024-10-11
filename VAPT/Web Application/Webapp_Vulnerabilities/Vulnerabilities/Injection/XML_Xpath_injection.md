https://owasp.org/www-community/attacks/XPATH_Injection
https://book.hacktricks.xyz/pentesting-web/xpath-injection

# What is XPath injection?

Similar to SQL Injection, XPath Injection attacks occur when a web site uses user-supplied information to construct an XPath query for 
XML data

By sending intentionally malformed information into the web site, an attacker can find out how the XML data is structured, or access data that they may not normally have access to. 

They may even be able to elevate their privileges on the web site if the XML data is being used for authentication (such as an XML based user file

Querying XML is done with XPath, a type of simple descriptive statement that allows the XML query to locate a piece of information. Like SQL, you can specify certain attributes to find, and patterns to match. 

When using XML for a web site it is common to accept some form of input on the query string to identify the content to locate and display on the page. This input must be sanitized to verify that it doesn’t mess up the XPath query and return the wrong data



# some example of xpath query
https://www.w3schools.com/xml/xquery_example.asp

Today XPath expressions can also be used in JavaScript, Java, XML Schema, PHP, Python, C and C++, and lots of other languages.

# XPath Injection Defenses

ust like the techniques to avoid SQL injection, you need to use a parameterized XPath interface if one is available, or escape the user input to make it safe to include in a dynamically constructed query. 

Another better mitigation option is to use a precompiled XPath1 query. Precompiled XPath queries are already preset before the program executes, rather than created on the fly after the user’s input has been added to the string. This is a better route because you don’t have to worry about missing a character that should have been escaped.


https://github.com/theand-fork/bwapp-code/blob/master/bWAPP/xmli_1.php
https://github.com/theand-fork/bwapp-code/blob/master/bWAPP/passwords/heroes.xml
https://github.com/theand-fork/bwapp-code/blob/master/bWAPP/xmli_2.php

payload for below  - ' or 'id'

if(isset($_REQUEST["login"]) & isset($_REQUEST["password"]))   
{ 

    $login = $_REQUEST["login"];
    $login = xmli($login);

    $password = $_REQUEST["password"];
    $password = xmli($password);
    
    // Loads the XML file
    $xml = simplexml_load_file("passwords/heroes.xml");
    
    // XPath search
    $result = $xml->xpath("/heroes/hero[login='" . $login . "' and password='" . $password . "']");
    
    // Debugging
    // print_r($result);  
    // echo $result[0][0];  
    // echo $result[0]->login;
    
    if($result)
    {
    
        $message = "<font color=\"green\">Welcome " . ucwords($result[0]->login) . ". Your secret: <b>" . $result[0]->secret . "</b></font>";
 
    }
    
    else
    {
        
        $message = "<font color=\"red\">Invalid credentials!</font>";        
        
    }

# ************************************************************************************************************************************
    // Playing with XML & XPath

    // Loads the XML file
    // $xml = simplexml_load_file("passwords/heroes.xml");

    // Debugging
    // print_r($xml);

    /*
    // Selects 1 attribute
    // $result = $xml->xpath("/heroes/hero/login");
    $result = $xml->xpath("//login");
    // Displays the result
    foreach($result as $row)
    {
        echo "<br />Found " . $row;
    }
    */

    /*
    // Selects all the attributes
    // $result = $xml->xpath("/heroes/hero");
    // $result = $xml->xpath("//hero[movie = 'The Matrix']|//hero/password");
    // print_r($result);
    // Displays the result
    foreach($result as $row)
    {
        // echo "Found "  . $row->login . "<br />";
        echo "<br />Found "  . $row->movie;
    }
    if($result)
    {
        echo "Found";
    }
    */

    /* Other queries
    $result = $xml->xpath("//hero[contains(password, 'trin')]"); // Selects all the attributes where the password contains 'trin'...
    $result = $xml->xpath("//hero[password = 'trinity']"); // Selects all the attributes where the password is 'trinity' ... (exactly)
    $result = $xml->xpath("//hero[login = 'neo' and password = 'trinity']"); // Selects all the attributes where ... and ... (exactly)
    $result = $xml->xpath("//hero[login = 'neo'][password = 'trinity']"); // Selects all the attributes where ... and within ... (query on query)
    $result = $xml->xpath("//hero[movie = 'The Matrix']/login"); // Selects the 'login' where the movie is 'The Matrix' (exactly)
    $result = $xml->xpath("//hero[movie = 'The Matrix']|//hero/password"); // Dangerous! Selects all the attributes from 1 movie and ALL the passwords
    $result = $xml->xpath("//hero[login/text()='" . $_GET["user"] . "' and password/text()='" . $_GET["pass"]  . "']"); // HTTP request params
     */

    /* More about XML and XPatch
    http://php.net/manual/en/simplexmlelement.xpath.php
    http://www.tuxradar.com/practicalphp/12/3/3
    https://www.owasp.org/index.php/XPATH_Injection
    https://www.owasp.org/index.php/XPATH_Injection_Java
    https://www.owasp.org/index.php/Testing_for_XPath_Injection_(OWASP-DV-010)
     */

}