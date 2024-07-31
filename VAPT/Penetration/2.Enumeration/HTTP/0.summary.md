# fingerprint the service using the tools available on the Kali machine (WhatWeb, Dirb, Browsh) and extract target server information.

Getting serivice information
root@attackdefense:~# `nmap 10.5.18.139 -p 80 -sV`

Getting info about headers and all
root@attackdefense:~# `whatweb 10.5.18.139`
root@attackdefense:~# `http 10.5.18.139`

Getting info about Directories and all
root@attackdefense:~# `dirb http://10.5.17.75 `


# Enumerated HTTP methods
root@attackdefense:~# `nmap -p 80 -sV 10.5.17.75 --script http-methods --script-args http-methods.url-path=/webdav/`

# Detect WebDAV configuration - etc.
root@attackdefense:~# `nmap -p 80 -sV 10.5.17.75 --script http-webdav-scan --script-args http-methods.url-path=/webdav/`

# Which web server software is running on the target server and also find out the version using nmap.
`nmap 192.102.102.3 -sV -p 80`
`nmap 192.102.102.3 -p 80 -sV --script banner`

# Which web server software is running on the target server and also find out the version using suitable metasploit module.
msf6 > `use auxiliary/scanner/http/http_version `
msf6 auxiliary(scanner/http/http_version) > `options`
msf6 auxiliary(scanner/http/http_version) > `set rhosts 192.102.102.3`
msf6 auxiliary(scanner/http/http_version) > `run`

# Check what web app is hosted on the web server using curl command.
root@INE:~# `curl 192.102.102.3 | more`

# Check what web app is hosted on the web server using wget command.
root@INE:~# `wget http://192.102.102.3/index`
root@INE:~# `cat index | more`

# Check what web app is hosted on the web server using browsh CLI based browser.
root@INE:~# `browsh --startup-url 192.102.102.3`

# Check what web app is hosted on the web server using lynx CLI based browser.
root@INE:~# `lynx http://192.102.102.3`

# Perform bruteforce on webserver directories and list the names of directories found. Use brute_dirs metasploit module.
msf6 > `use auxiliary/scanner/http/brute_dirs`
msf6 auxiliary(scanner/http/brute_dirs) > `options`
msf6 auxiliary(scanner/http/brute_dirs) > `set rhosts 192.102.102.3`
msf6 auxiliary(scanner/http/brute_dirs) > `run`

# Use the directory buster (dirb) with tool/usr/share/metasploit-framework/data/wordlists/directory.txt dictionary to check if any directory is present in the root folder of the web server. List the names of found directories.
root@INE:~# `dirb http://192.102.102.3 /usr/share/metasploit-framework/data/wordlists/directory.txt `

# Which bot is specifically banned from accessing a specific directory?
Badbot - it can be found in robots.txt