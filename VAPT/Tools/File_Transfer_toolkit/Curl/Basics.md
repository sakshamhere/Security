


# Flags

-X 
    --request <method>
              (HTTP)  Specifies  a  custom  request  method to use when communicating with the HTTP server. The specified request method will be used instead of the method otherwise used (which defaults to GET). Read the HTTP 1.1
              specification for details and explanations. Common additional HTTP requests include PUT and DELETE, but related technologies like WebDAV offers PROPFIND, COPY, MOVE and more.

-I            -I flag to simply print out the header information of all requested pages.

-s            -s flag to prevent the progress of the error messages from being displayed

# common commands

- curl -X OPTIONS https://example.org -i

- curl 192.168.46.129/dvwa/index.php -v --cookie "PHPSESSID=f66d830e5de090ce479d98c1ec88477a"

- curl -I demo.testfire.net