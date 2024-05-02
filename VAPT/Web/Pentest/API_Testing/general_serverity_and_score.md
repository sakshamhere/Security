

#  VULNERABILITY                                            SEVERITY           OWASP_CATAGORY          CWE ID

* POOR ERROR HANDELING: UNHANDLED EXCEPTION                 LOW             SECURITY MISCONFIGURATION

* IMPROPER RESTRICTION OF EXCESSIVE AUTHENTICATION ATTEMPTS LOW             IMPROPER AUTHENTICATION

* MISSING HTTP-STRICT TRANSPORT SECURITY HEADER             LOW             SECURITY MISCONFIGURATION

* COOKIE SECURITY: COOKIE NOT SENT OVER SSL                 LOW             CRYPTOGRAPHIC FAILURES

* HTML 5 CROSS-ORIGIN RESOURCE SHARING                      LOW             SECURITY MISCONFIGURATION

* IMPOPER INPUT VALIDATION                                  MEDIUM          INJECTION


********************************************************************************************************************************************
# POOR ERROR HANDELING: UNHANDLED EXCEPTION

In Xyz app API due ti unhandeled input, server is throwing java lang NumberFormatException on being unabke to parse the user input. Hence the information about backend technology is being revelaed/leaked due to unhandeled error.

* Remediation

The exception needs to be handle with a generic error Message.

********************************************************************************************************************************************
# IMPROPER RESTRICTION OF EXCESSIVE AUTHENTICATION ATTEMPTS 

It was found the XYZ API does not have account lockout mechenism inplemented properly, (API uses Basic Auth)

Send the request with "Authorization: Basic akgjjsoiduefllsji23kd " header to burp intruder and select the auth token as payload, choose attack type sniper.

In payloads add 10 random and for 11th value add out token.

Start attack, we observe that lenght of request 0 and our auth token are same, this proves that application could be vulnerable to brute force attack.

Although these type of attacks are time consuming but are successful in harvesting username and apssword.

* Remediation

It is recommended that an automatic account lockout after a few failed attempt be implemented.


********************************************************************************************************************************************
# MISSING HTTP-STRICT TRANSPORT SECURITY HEADER

It is observed that xyz-API failed to implement HSTS header (we observed `Strict-Transport-Security: max-age=0`)

* Remediation

Demo Implementation - `Strict-Transport-Security:max-age=60000; includeSubDomains`

- Transparently redirect users to this secure connection regardless of how they come to the site by sending a 301 HTTP Response.

- Make sure that all user's sensetive session information uses only secure connection by adding a secure keyword when sestting cookies.

- Send a Strict -Transport-Security header to make sure users always visit the site over HTTPS, and never accidently open a window of opportunity for active network acctakers.

********************************************************************************************************************************************
# HTML 5 CROSS-ORIGIN RESOURCE SHARING 

It was found that xyz API is vulnerable to Cross-Origin Sharing attack.

In the response we can see ` Access-Control-Allow-Origin: * ` which means appolication allows access from any domains

* Remediation

Domains that are allowed should be reviewd, the application should take prevention for allowing origin as wildcard value `*` or `null` character.

********************************************************************************************************************************************
# IMPOPER INPUT VALIDATION 

It is observerd xyz API is vulnerable to Improper Input Validation, it was the injected payload was getting reflected without any sanitization or filteration.

*Remediation
same as for XSS
********************************************************************************************************************************************
********************************************************************************************************************************************
********************************************************************************************************************************************
********************************************************************************************************************************************
********************************************************************************************************************************************
********************************************************************************************************************************************
********************************************************************************************************************************************
