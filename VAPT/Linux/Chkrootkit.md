
# Rootkit

https://www.veracode.com/security/rootkit

A rootkit is a clandestine computer program designed to provide continued privileged access to a computer while actively hiding its presence. 

Originally, a rootkit was a collection of tools that enabled administrator-level access to a computer or network. Root refers to the Admin account on Unix and Linux systems, and kit refers to the software components that implement the tool. 

Today rootkits are generally associated with malware – such as Trojans, worms, viruses – that hide their existence and actions from users and other system processes.

A rootkit allows someone to maintain command and control over a computer without the computer user/owner knowing about it. Once a rootkit has been installed, the controller of the rootkit has the ability to remotely execute files and change system configurations on the host machine. 

Example - `Stuxnet` - the first known rootkit for industrial control systems

# Checkrootkit

https://www.geeksforgeeks.org/detecting-and-checking-rootkits-with-chkrootkit-and-rkhunter-tool-in-kali-linux/

It is a free and open-source antivirus tool available on GitHub. This tool checks locally in the binary system of your machine and scans your Linux server for a trojan. chkrootkit is a shell script which checks system binaries for rootkit modification.  This tool is used for scanning botnets, rootkits, malware, etc. 

# NOTE - `Versions less that 0.5.0 is vulnerable to Local Privilege Escalation`

jackie@victim-1:~$ `chkrootkit --help`
chkrootkit --help
Usage: /bin/chkrootkit [options] [test ...]
Options:
        -h                show this help and exit
        -V                show version information and exit
        -l                show available tests and exit
        -d                debug
        -q                quiet mode
        -x                expert mode
        -r dir            use dir as the root directory
        -p dir1:dir2:dirN path for the external commands used by chkrootkit
        -n                skip NFS mounted dirs
jackie@victim-1:~$ 