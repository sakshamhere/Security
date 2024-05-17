
# generating using `openssl`

student@attackdefense:~$ `openssl passwd -1 -salt abc password123`
$1$abc$UWUoROXzUCsLsVzI0R2et.

# we can also generate using `mkpasswd` on kali

┌──(kali㉿kali)-[~]
└─$ `mkpasswd -m sha-512 newpasswordhere`
$6$oTvKrJiKZIcu/MLj$q8t7Ip.Plc4rfdRjyUlL9bEx2loeDcROEHph.syr/7.56YGKAPUMNkMQpavEbGo7T3nt/XXZDsuAiz7DlVFpQ.
