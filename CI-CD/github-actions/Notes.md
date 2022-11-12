Workflow - workflow file is a yaml file placed in .github/workflow folder

Events(eg push,pull)

Jobs(steps within a workflow grouped together)

Actions(custom code for a task)

Runner (its the same as agent)

*****************************************************************
# Syntex of YAML

name: Run Shell command
on: [push,fork etc]
jobs:
    run-shell-command:
        runs-on: ubuntu-latest
        name: xyz
        steps:
        - name: xyz
          run: echo "hellow world"