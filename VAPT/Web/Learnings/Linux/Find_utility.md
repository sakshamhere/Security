https://www.geeksforgeeks.org/find-command-in-linux-with-examples/

# Utility designed for comprehensive file and directory searches 

`-name pattern` - Searches for files with a specific name or pattern.

`-type type`    - Specifies the type of file to search for (e.g., f for regular files, d for directories).

`-size [+/-]n `   - Searches for files based on size. `+n` finds larger files, `-n` finds smaller files. ‘n‘ measures size in characters.

`-mtime n  `      - Finds files based on modification time. `n` represents the number of days ago.

`-exec command {} \;` - Executes a command on each file found.

`-print   `         - Displays the path names of files that match the specified criteria.

`-maxdepth levels`    - Restricts the search to a specified directory depth.

`-mindepth levels`  - Specifies the minimum directory depth for the search.

`-empty `     - Finds empty files and directories.

`-delete`   - Deletes files that match the specified criteria.

`-execdir command {} \;` - Executes a command on each file found, from the directory containing the matched file.

`-iname pattern ` - Case-insensitive version of `-name`. Searches for files with a specific name or pattern, regardless of case.

There are many more endlsess....options

Below are some useful examples for the “find” command.

Find files:

`find . -name flag1.txt:` find the file named “flag1.txt” in the current directory
`find /home -name flag1.txt: `find the file names “flag1.txt” in the /home directory
`find / -type d -name config:` find the directory named config under “/”
`find / -type f -perm 0777: `find files with the 777 permissions (files readable, writable, and executable by all users)
`find / -perm a=x: `find executable files
find /home -user frank: find all files for user “frank” under “/home”
`find / -mtime 10:` find files that were modified in the last 10 days
`find / -atime 10: `find files that were accessed in the last 10 day
`find / -cmin -60:` find files changed within the last hour (60 minutes)
`find / -amin -60:` find files accesses within the last hour (60 minutes)
`find / -size 50M:` find files with a 50 MB size

This command can also be used with (+) and (-) signs to specify a file that is larger or smaller than the given size. 

************************************
EXAMPLES

# Find a file named “sample.txt” within the “GFG” directory.

- find ./GFG -name sample.txt

# Find files ending with ‘.txt’ within the “GFG” directory.

- find ./GFG -name *.txt 

# Find and delete a file named “sample.txt” within the “GFG” directory.

- find ./GFG -name sample.txt -exec rm -i {} \; 

# discovering and listing empty files and directories within a specified directory.

- find ./GFG -empty

# Find files with permissions set to 664 within the “GFG” directory.

- find ./GFG -perm 664

# Display the hierarchical structure of repositories and sub-repositories within a given directory.

- find . -type d

# look for lines containing the word ‘Geek’ within all ‘.txt’ files in the current directory and its subdirectories.

- find ./ -type f -name "*.txt" -exec grep 'Geek'  {} \;