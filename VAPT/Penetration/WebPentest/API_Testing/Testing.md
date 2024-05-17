
# https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/web-api-pentesting#tricks


* These are techniques apart from known vul to see how server behaves to unexpected requests

# Wildcard parameter

Try to use the following symbols as wildcards: *, %, _, .

/api/users/*
/api/users/%
/api/users/_
/api/users/.

# HTTP request method change

You can try to use the HTTP methods: GET, POST, PUT, DELETE, PATCH, INVENTED to try check if the web server gives you unexpected information with them.


# Request content-type

Try to play between the following content-types (bodifying acordinly the request body) to make the web server behave unexpectedly:

- x-www-form-urlencoded --> user=test
- application/xml       --> <user>test</user>
- application/json      --> {"user": "test"}