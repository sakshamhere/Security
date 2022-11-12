# What is SQLi      https://www.youtube.com/watch?v=1nJgupaUPEQ
SQL injection testing checks if it is possible to inject data into the application so that it executes a user-controlled SQL query in the database. Testers find a SQL injection vulnerability if the application uses user input to create SQL queries without proper input validation A successful exploitation of this class of vulnerability allows an unauthorized user to access or manipulate data in the database.

# Types of SQLi

SQL Injection attacks can be divided into the following three classes:

- Inband (Classic): This is when attacker is able to use same coomuncation channel to attack and extract data This is the most 
                    straightforward kind of attack, in which the retrieved data is presented directly in the application web page.

    - Error:    This technique forces the database to generate an error, giving the attacker or tester information upon which to refine 
                their injection.
                An Example would be that if we have parameter that is vulnerable to SQL injection and you put a comment delimeter(",' etc) which breakes backend query and generates an error and error tells you version of database or some other informatrion

    - Union     This technique uses UNION opoerater to combine two query into one result set, this way we can also output result of 
                query of our choice with the existing


- Inferential(Blind): there is no actual transfer of data from the application and we dont see the results, instead we ask application
                      true/false questions or causing the database to pause for a specified time in order to determine that what we are asking is correct or not

    - Boolean
    - Time based

- Out-of-band (OAST): This oucours when the attacker is unable to use the same channel to launch attack and gather the results, It 
                      usually relies on the ability to make a network connection for example a DNS or HTTP request to deliver data to attacke.
               
               Although people see this in Blind sql injection but many resource makes three categories.
                

# How to Test/Find Vulnerability

Black Box Perspective

- Map the application  - That means, visit URl of app, walkthrough all the pages, make note of input vectors that talk to the backend, 
                         figure out how application functions and the logic, find subdomains, enumerate directories and pages that are not directly visibel

- Fuzz the application - submitting SQL specific characters such as ' or ", and look for error or other anomalies
                       - submitting Boolean condiions such as 1=1 OR 1=2 and look for diffrences in application responses
                       - submitting Payload designed to trigger time delays when executed within a SQL query and look for diff in time 
                         taken in responses
                       - submitting OAST payloads designed to trigger an Out-Of-Band network interaction when executed within an SQL    query and monitor for resulting interactions

White Box Perspective
                    - Enable database logging
                    - Enable WebServer logging
                    - Map the application 
                    - Code Review

# Prevention

* Primary Defences

    - Use of Prepared Statements( Parameterized Queries ) - In this the query structure gets already fixed before the input is added in 
                                                          query and hence its not vulnerable to SQLi

    Partial Defence Options (not so effective)
          The reason people use partial defences is because there are certain parameters that cant be specified in Prepared parameter placeholder in prepared statements example table name

        - Use of Stored Procedures
            - A stored procedure is batch of statements grouped together and stored in database
            - Not always safe from SQL injection because if its implemented incorrectly it could still lead to SQLi
        
        - Whitelist Input Validatation
            - Defining what values are authorised, everything else is considered unauthorized
            - Useful for values that cannot be specified as parameter placeholders, such as table name

* Additional Defences (Defence in depth)

    - Least Privilage
            
            - The application should use the lowest possible level of privilage when accessing the database
            - Any unnecessory default functionality in the database should be removed or disabled for example functions that allow to 
              make a network connection leading to OAST (out of band sqli)
            - Ensure CIS benchmark for databse in use is applied
            - All vendor issued security patched should be applied in timely fasshion



# Retrieving hidden data, 
where you can modify an SQL query to return additional results.

for example using payload like: or 1=1--

https://portswigger.net/web-security/sql-injection
https://www.youtube.com/watch?v=X1X1UdaC_90

# Subverting application logic,
where you can change a query to interfere with the application's logic.

for example login without even using password by payload: 'or 1=1-- 

# ********************************************************* UNION attacks ***********************************************************
where you can retrieve data from different database tables.

When an application is vulnerable to SQL injection and the results of the query are returned within the application's responses, the UNION keyword can be used to retrieve data from other tables within the database. This results in an SQL injection UNION attack.

To carry out an SQL injection UNION attack, you need to ensure that your attack meets these two requirements. This generally involves figuring out:

# Determining How many columns are being returned from the original query?

- Method 1 - The first method involves injecting a series of [ORDER BY] clauses and incrementing the specified column index until an error occurs
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
etc.

- Method 2 - 
The second method involves submitting a series of UNION SELECT payloads specifying a different number of null values:

' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
etc.

it gives error untill number of null dosent match number of columns

# Determining which column is string data type, by placing a string once in every NULL place

' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--


* When you have determined the number of columns returned by the original query and found which columns can hold string data, you are in a position to retrieve interesting data.

# Examining the database, where you can extract information about the version and structure of the database.

When exploiting SQL injection vulnerabilities, it is often necessary to gather some information about the database itself. This includes the type and version of the database software, and the contents of the database in terms of which tables and columns it contains

The queries to determine the database version for some popular database types are as follows:

Database type	                Query
Microsoft, MySQL	            SELECT @@version
Oracle	                        SELECT * FROM v$version
PostgreSQL	                    SELECT version()

For example, you could use a UNION attack with the following input:

' UNION SELECT @@version--

4. Listing the contents of the database


# Using an SQL injection UNION attack to retrieve interesting data

Step 1 - Find the number of columns exist by using ORDER BY or UNION NULL..

Step 2 - Find the columns that are having str data type

Step 3 - Find the type of database it is like Microsoft,mysql, postgresql or oracle

step 4 - find the table names from it 

step 5 - find the column name from the suspected table

step 5 - find the data from column from the table 

Gifts'+union+select+username_otjdfc,password_tnythx+from+users_gpyojw+--