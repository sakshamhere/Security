https://www.redhat.com/sysadmin/nmap-scripting-engine

Using NSE scripts with Nmap allows you to scan different hosts and find vulnerabilities in services running on the host and possibly log in by brute-forcing these services.

The use of NSE script syntax is as follows:

# nmap --script="name_of_script" --script-args="argument=arg" target

What is the NSE? This tool does two things. First, it allows the nmap command to accept options that specify scripted procedures as part of a scan. Second, it enables Nmap users to author and share scripts, which provides a robust and ever-evolving library of preconfigured scans.

NSE script types

NSE scripts are organized into 14 categories on the NSE Scripts documentation page. Many categories are security-oriented, while others hint at discovery and troubleshooting.

Some of the more interesting categories are:

    broadcast
    default
    discovery
    intrusive
    vuln

The primary option to add common NSE scripts to the nmap command is -sC. 

The --script option defines which script to run if you're using your own script. 

nmap -sC executes a scripted scan using the scrips in the default category. 

# exampls

- nmap -sV --script banner <target>                                                                      (to find banner)
- nmap -p 80 --script http-methods  192.168.46.129                                                      (to find HTTP methods availible)
- nmap -p 443 --script http-methods --script-args http-methods.url-path='/index.php' localhost          
- nmap -p 80 --script http-methods --script-args http-methods.url-path='/index.php' 192.168.46.129

- nmap -p443 --script http-waf-detect --script-args="http-waf-detect.aggro,http-waf-detect.detectBodyChanges" www.slimmer.ai