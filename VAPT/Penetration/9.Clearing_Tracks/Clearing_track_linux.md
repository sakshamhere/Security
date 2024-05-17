
1. always save your files in `tmp` folder, its already present in linux most of the time

# Good things is the artifacts in this folder automatically gets removed after system restart

2. Similat to Windows we use `Resource Scripts` in linux as well, for artifacts left by post exploitation modile

3. All users bash history in linux is stored in `.bash_history` file, make sure you delete its content

┌──(root㉿kali)-[/home/var]
└─# `ls -l ~/.bash_history`

There are two ways you can delete histiory
1. go and manually delete entries in it
2. we can use `history -c` 
