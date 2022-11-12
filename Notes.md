
The DevSecopsszdfsdf

Security verifications and checks are incorporated at different points of the DevOps pipeline

# Plan
- In this phase, the security issues to be addressed in the next few sprints are decided.
- Threat modeling and data flow diagrams are worked upon in this phase

# Code
- The coding phase involves choosing security tools and solutions that integrate within the developer environment.
- Security architecture review, inspections and environment hardening is to be carried out during this phase.
- Security scanning should involve scanning of third-party libraries for known vulnerabilities at cve mitre site
- Security code review using automated tools, as well as manual review

# Test
- Interactive application security testing aids in analyzing the application from a user's point of view.
- Web Application Vulnerability Scanners are automated tools that can scan web applications, typically from outside, to look for various security vulnerabilities such as cross-site scripting, SQL injection, command injection, path traversal, and insecure server configuration.

# Release
- In the release phase, further security checks can be performed by using penetration testing.

# Deploy
- During the configuration phase, binaries need to be signed and timestamped to facilitate integrity checks for release.
- The signature should be verified before deploying it into the CI/CD pipeline.

# Operate
- Involves checking the signature of the binaries
- Focuses on configuration assurance at instantiation by security controls like defense-in-depth

# Monitor
- Continuous monitoring helps in detecting irregular behavior in production.
- Technologies such as RASP can be leveraged.

# ***********************************************************************************************************************

# Design
 - Threat Modelling -  
 
Threat modeling is a planned activity for recognizing and evaluating application threats and vulnerabilities.
Threat modeling can be applied to a wide range of applications, including software, systems, networks, distributed systems, components of the Internet of Things, and business processes.

Threat modelling models an application and looks for vulnerabilities, this is often done by a data flow diagram and then mapping elements using STRIDE

we check elements for

Spoofing user identity
Tampering
Repudiation
Information disclosure
Denial of Service
Elevation of privilage


# Implementation
- Static Code Analysis

Static Analysis is defined as the method of debugging by automatic examination of source code before program execution.
Static code analysis is performed in the early stages of SDLC, that is, during the development phase, before testing begins.    
For organizations practicing DevOps, static code analysis takes place during the Create phase.

# Testing
- Dynamic Code Analysis

Dynamic code analysis is the process of analyzing an application during its execution.
It identifies defects after you run a program (for example, during unit testing).
It can be performed based on the principles of White Box testing and Black Box testing.

# Deploy
- OS Hardening, Web/Application Hardening

Hardening of the application is the act of configuring an application securely, updating it, creating rules and policies to help govern the application in a secure manner, and removing unnecessary applications and services.
This is done to minimize a computer OS's exposure to threats and to mitigate possible risks.

# Maintain and Monitor
- Security Monitoring/Compliance

Security Information and Event Management (SIEM).
Infrastructure Monitoring - Nagios, Zabbix, Sensu, Prometheus, SysDig and New Relic Infrastructure, AWS CloudWatch and Google StackDriver
Application Performance Monitoring - New Relic, AppDynamics, Compuware APM and Boundary

# *********************************************************************************************************************

# SCA / Software Composition Analysis

Component Analysis is the method of identifying potential risk areas from the use of software and hardware components from third parties or open-source.

# SCA Tools

Software Composition Application tools can be classified as follows:

- Static Application Software Testing (SAST) tools 

A SAST tool should be capable of properly scanning most of the popular languages as applications generally use more than one language.

These tools primarily scan the source code, and may also look into the binaries and configuration files.

The important aspect is that these tests can be done without running the application.

There is no need to make an actual operational setup.
Since SAST requires access to secure code, it is also known as white box testing.

popular open-source tools - SonarQube, FindBugs, Brakeman, Trufflehog, Bandit, Python Taint
licensed tools. - Micro Focus Fortify, CheckMarx, IBM AppScan, Veracode Static Analysis

- Dynamic Application Software Testing (DAST) tools 

DAST tools are deployed as part of a more security-forward approach to the development of web applications. These tools provide insight into the actions of web applications while they are in development, helping a company to fix possible vulnerabilities before they are used by a hacker to attack.

As web applications evolve, DAST tools keep scanning them so that business can identify emerging issues without delay before they develop into serious risks.

Example - BURPSUITE, Nikto

# Compliance as Code

- Achieving Compliance Using Configuration Management

Configuration management tools like Puppet, Chef, and Ansible can achieve compliance.
These tools are known for managing, organizing, and monitoring the changes in codes and other entities systematically.

- Compliance using InSpec at Scale

Chef InSpec is a free and open-source framework for testing and auditing your applications and infrastructure.
*******************************************************************************************************************

# DevSecOps Tools

During Development Stage

* Git Secrets - to identify any kind of security credentials or personal tokens that are in source code by mistake by scanning entire code repo

* Security Plugin in IDE

During Build pipeline stage

* Code Quality tools (Sonarqube)

* SAST security tools (fortify,Veracode, Checkmarkx etc)

*DAST security tools (OWASP ZAP, WebInspect, Veracode etc)

* IAC security tools (Bridgecrew, Synk)

* Container security tools (Aqua, Prism, Qualys)

* CSPM tools

* Container registry scanning tools

* Cloud security tools (AWS security hub, Azure Defender)