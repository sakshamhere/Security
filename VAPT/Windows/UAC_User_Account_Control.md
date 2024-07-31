# UAC User Account Control

`How does UAC work? `When a user with an account type of administrator logs into a system, the current session doesn't run with elevated permissions. When an operation requiring higher-level privileges needs to execute, the user will be prompted to confirm if they permit the operation to run.

UAC ensure that changes to OS requires approval from the administrator or a user account that is part of local administrator group

A non Privileged user attempting to execute a program with elevated privileges will be prompted with `UAC Credential Prompt`

While if a Privileged user attempts to execute a program with evelated privileges will be prompted with `UAC Consent Prompt`

Attackers can bypass UAC in order to execute malicious executables with elevated privileges.

# UAC Level

UAC has LOW to High levels, if it is configured below High then elevated progams may be executed without prompt

# Bypassing UAC

In order to Bypass UAC we need to have user account that is part of Local Administrators Group on target machine