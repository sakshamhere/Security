
Previously developer used JavaBeans and had challanges
- not able to provide services, such as transaction management and security
- complex code

# Spring

The Spring framework(which is commonly known as Spring) has emerged as a solution to all these complications This framework uses various new techniques such as 

- Aspect-Oriented Programming (AOP)
- Plain Old Java Object (POJO)
- dependency injection (DI), 

to develop enterprise applications

The Spring framework can be considered as a collection of sub-frameworks, also called layers, such as 

- Spring AOP
- Spring Object-Relational Mapping (Spring ORM)
- Spring Web Flow
- Spring Web MVC.

# Features

1. IoC container
Refers to the core container that uses the DI or IoC pattern to implicitly provide an object reference in a class during runtime.
The Spring framework provides two packages, namely 
- org.springframework.beans
- org.springframework.context 
which helps in providing the functionality of the IoC container.

2. Data access framework: 
Allows the developers to use persistence APIs, such as JDBC and Hibernate, for storing persistence data in database. 

3. Spring MVC framework: 
Allows you to build Web applications based on MVC architecture. All the requests made by a user first go through the controller and are then dispatched to different views, that is, to different JSP pages or Servlets. The form handling and form validating features of the Spring MVC framework can be easily integrated with all popular view technologies such as ISP, Jasper Report, FreeMarker, and Velocity.

4. Spring Web Service
Spring Web Service provides layered-based approaches that are separately managed by Extensible Markup Language (XML) parsing (the technique of reading and manipulating XML). Spring provides effective mapping for transmitting incoming XML message request to an object and the developer to easily distribute XML message (object) between two machines.

5. JDBC abstraction layer: 
Helps the users in handling errors in an easy and efficient manner. The JDBC programming code can be reduced when this abstraction layer is implemented in a Web application.


# Architecture
The Spring framework consists of seven modules

1. Spring Core
2. Spring AOP Aspect-Oriented Programming (AOP)
3. Spring Web MVC
4. Spring DAO
5. Spring ORM
6. Spring context
7. Spring Web flow.

1. Spring Core

Spring Core provides the IoC container, which contains two types of implementation

- `Bean Factory` defined using org.springframework.beans
- `Application Context` defined using org.springframework.context 



Spring Core
- Dependency Injection

Spring MVC
- Web dev
    - In this we genrally work with Tomcat, and in tomcat everything ultimately comverts into servlets (so knowing servlet and JSP is good)

Spring Rest
- Rest APIs


Core Java - ok
JDBC
Tomcat, Servlet and JSP
ORM Framework - Hibernate
