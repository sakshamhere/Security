Redis began as a caching database, but it has since evolved into a primary database. Many applications built today use Redis as a primary database.  

Redis is a in-memroy database, it dosent store data on disk like mariadb, mysql etc, it is very fast, but also data can be lost if its restarted, it is maily used for real-time applications

However, most Redis service providers support Redis as a cache but not as a primary database. This means you need a separate database like DynamoDB in addition to using Redis. This adds complexity, compromises latency, and prevents you from realizing the full potential of Redis.

With Redis Enterprise, you can use Redis as both an in-memory cache and a primary database in a single system, thus eliminating the complexity and latency of two separate systems. 


Basic commonds

- redis-cli -h 10.129.8.175               (-h is for host)

-redis-cli -v 10.129.8.175  (for version)

- info  (once connected we can type info to get all details including the db)

- select (to select the database)

- keys *        (command is used to obtain all the keys in a database, once you select it)

- get "key"     (to get value of key)

NOTES

- Which command-line utility is used to interact with the Redis server? Enter the program name you would enter into the terminal without any arguments. 
Answer - redis_cli

Once connected to a Redis server, which command is used to obtain the information and statistics about the Redis server
Answer - info