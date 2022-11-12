# git config
to configure your username and email, so that anyone who sees you commit gets idea who has commited

# git init

# git add 
- git add <filename> , git add . or git add -A

# git commit
- git commit -m "some message"

now if we dont want to add and move code to staging area agin n agin we can direclty commit it by using below
- git commit -a -m 'message'

this will only work if the file is tracked already, ie it should be added once atleast to move into tracking

# git checkout
- git checkout <filename> = when you want to undo to your last commit to a file
- git checkout -f = when you want to undo to your last commit to all file
- git checkout --orphan <new branch name> = direct checkout and create new branch
- git checkout -b <new branchname> = direct checkout and create new branch
- git checkout <branchname> = when you want to move to diff branch

# git branch
- git branch <branchname> =  create new branch
- git checkout --orphan <new branch name> = direct checkout and create new branch
- git checkout -b <new branchname> = direct checkout and create new branch
- git branch -D <branchname> = delete branch
- git branch -m <newname> = rename the branch you are in

# git push
- git push origin <branchname>
- git push -f orgin <branchname> = force push

# git log
- git log = gives you all the log like what and who commited last
- git log -p -<number of commites> = in ca we want to see last 5 commits only

# git diff

when we want to compare working dir and stagin area

- git diff = gives you the changes you have made to a file which is not added

this gives you diffrence between you working dir and staging area, so if we do git add . and then git diff it wont show anything as everything now will be same in working dir and staging area 

Now if want to compare staging area from last commit we can use below command

- git diff --staged

# git rm

- git rm <filename> = this will remove file from working directlry itself
- git rm --cached <filename> = this will only remove file from stagin area not from hard disk/working dir

# git status
- git status = to know the current status
- git status -s = this will give you a sumarize status of what being modified in what are(staging area/working area)

# git remote
- git remote add origin <url> = to add an remote git repo
- git remote = list the number of remote repo availible ex origin
- git remote set-url origin <new url> = in case you want to add another url for example when you switched to ssh