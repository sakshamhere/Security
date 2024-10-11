
# Cron Jobs

Linux Implement Task Scheduling through a utility called `Cron`

Cron is a time based service that runs applications scripts and commands repeatedly on a specified schedule.

An application that has been configured to run repeatedly with `Cron` is called `Cron Job`.

`Cron` can be used to automate or repeat variety of functions on a system, from daily backups to system upgrades and patches

Cron jobs are used to run scripts or binaries at specific times. By default, they run with the privilege of their owners and not the current user. While properly configured cron jobs are not inherently vulnerable, they can provide a privilege escalation vector under some conditions.
The idea is quite simple; if there is a scheduled task that runs with root privileges and we can change the script that will be run, then our script will run with root privileges.

Cron job configurations are stored as crontabs (cron tables) to see the next time and date the task will run.

Each user on the system have their crontab file and can run specific tasks whether they are logged in or not. As you can expect, our goal will be to find a cron job set by root and have it run our script, ideally a shell.

Any user can read the file keeping system-wide cron jobs under `/etc/crontab`


# `Crontab File`

`crontab file` is a configuration file that is used by `cron` utility to store and track `Cron Jobs` that have been creates.

└─$ `crontab --help`
crontab: invalid option -- '-'
crontab: usage error: unrecognized option
usage:  crontab [-u user] file
        crontab [ -u user ] [ -i ] { -e | -l | -r }
                (default operation is replace, per 1003.2)
        -e      (edit user's crontab)
        -l      (list user's crontab)
        -r      (delete user's crontab) 
        -i      (prompt before deleting user's crontab)

# My Cronjob for git commit code automatically every 10 min

(note that files are auto saved by setting- File -> Preferences -> Settings and type auto save(onfocuschange))

*/10 * * * * (cd /home/kali/Security && git add . && git commit -m "Automatic Commit" && git push)   


