# 1. Testing Directory Traversal/File include

- check for directory traversal,    Remote file inclusion,   local file inclusion

# 2. Testing for bypassing Autorization schema

- Accessing a resource without authentication

- bypass ACL (access control list)

- check for force browsing (/admin/main.php, /page.asp?authenticated=yes)

# 3. Testing for Privilage Esclation

- Testing for role/privilage esclation, manupilating values of hidden parameters

# 4. Testing for Insecure Direct Object Reference

- Force changing paramters values (?invoice=123 -> ?invoice=234)