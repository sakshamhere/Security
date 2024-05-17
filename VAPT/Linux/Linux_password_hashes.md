
Similar to Windows Linux also has multi-user suppoprt which can acces the system simulteniosly.All the information for all accounts on linux is stored in the `passwd` file at `/etc/passwd`

All user have read access to `/etc/passwd` however cannot read passwords in it as they are encrypted.

All the encrypted passwords are stoerd in `shadow` file at `/etc/shadow` in hash fornmat, and only root account can access it.

# We can determine the `Hashing algorithm` used to password hashing by below Value, this value with $ is appended with hash of password

#   Value           Hashing Algo

    $1              MD5
    $2              BlowFish
    $5              SHA-256
    $6              SHA-512


# Example `$6$` below

meterpreter > `cat /etc/shadow`
root:$6$sgewtGbw$ihhoUYASuXTh7Dmw0adpC7a3fBGkf9hkOQCffBQRMIF8/0w6g/Mh4jMWJ0yEFiZyqVQhZ4.vuS8XOyq.hLQBb.:18348:0:99999:7:::
daemon:*:18311:0:99999:7:::
bin:*:18311:0:99999:7:::
sys:*:18311:0:99999:7:::
sync:*:18311:0:99999:7:::
games:*:18311:0:99999:7:::
man:*:18311:0:99999:7:::
lp:*:18311:0:99999:7:::
mail:*:18311:0:99999:7:::
news:*:18311:0:99999:7:::
uucp:*:18311:0:99999:7:::
proxy:*:18311:0:99999:7:::
www-data:*:18311:0:99999:7:::
backup:*:18311:0:99999:7:::
list:*:18311:0:99999:7:::
irc:*:18311:0:99999:7:::
gnats:*:18311:0:99999:7:::
nobody:*:18311:0:99999:7:::
_apt:*:18311:0:99999:7:::
meterpreter > 