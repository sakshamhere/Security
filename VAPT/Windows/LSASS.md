https://redcanary.com/threat-detection-report/techniques/lsass-memory/
https://attack.mitre.org/techniques/T1003/001/

# Local Security Authority Subsystem Service


Adversaries commonly abuse the `Local Security Authority Subsystem Service (LSASS)` to dump credentials for privilege escalation, data theft, and lateral movement


The process is a fruitful target for adversaries because of the sheer amount of sensitive information it stores in memory. Upon starting up, LSASS contains valuable authentication data such as:

    encrypted passwords
    NT hashes
    LM hashes
    Kerberos tickets