Azure Devops

# Azure BOARDS

Planning is the first step, what are we going to develop and how

There are workflow like SCRUM (framework to implement agile) which help in splitting tasks and providing roles etc

The very first thing we do in Azure Devops is Boards, we can choose type (Agile, Scrum, basic, CMMI) on the basis of our workflow

The developers are assigned tasks,

developer can also communicate with other on boeards

borads can be used to have an overview of feature as being developed

# Azure Repos

Now since the code is being developed by developers its can be hosted in Azure Repo

Azure Repos supports git

Azure Repos is not just limited to hosting code, as part of the Git Workflow we have features such as Pull Request, Branches and so pn..

So when developers perform task they create a temprory branch and other can pull request, they can communicate and collaborate untill the code is good enough to be pushed to main branch

The Azure Repos commit are also linked to feature tasks in Boards, so we see activity ands status of developement there as well

# Azure Pipelines

Now once the code is merged into the main branch we want to release in order to release new feature

So in order to release we need to Test and package it into an artifact as a deliverable to be deplyed in any env ie dev,test or prod

This thing can be automated using azure pipelines

We create this in YAML files

Basically we Have "Stages" which represent our diff env like build & test, Deploy 
within those stages we have our "jobs" running on agent
within those jobs we have our "Steps" which execute "Task" or "scripts"

* Templates

The code for diff env ie diffrent stages is mostly same except for some paramenters so we can avoid repeating the pipeline configuration code 

or may be we have multiple application with similar pipeline configuration code, so we dont want to write code for each again

Instead we ideally write a logic once in a file and reuse it, this file can be refreced as Temlate in our job and we can give paramerters for it

- stage: Deploy dev
  job:
  - template: /Deploy/jobs/deploy.yml
    parameters:
        env: Dev

- stage: Deploy test
  job:
  - template: /Deploy/jobs/deploy.yml
    parameters:
        env: Test

- stage: Deploy prod
  job:
  - template: /Deploy/jobs/deploy.yml
    parameters:
        env: Prod

You can have template at any level ie you can have it for a Stage, job or even a Step

we can also have templates within the templates

# Enviornments

When we have multiple envirments it becomes difficult what version of which branch is deployed where or when the code was last deployed to any specific env and so on

so we can create envirment and them mention them in our pipeline which will map to actual deployment env

- stage: Deploy prod
  job:
  - deployment: deploy to deployment 
    enviorment: developement
    steps:
    - task: Azurewebapp@1   

Once this done we actually have View of deployemnt history in Enviorment in Azure Devops

These can also be liked to azure borads so that there we have overview of which env is being deployed 

# Release pipeline

Although we can have configuration wittern for deployment in same yaml file we can also create a release pipeline sepearatly

Many CI CD platform like Jenkins Gitlab CICD have one pipeline for whole cicd process but here we have two

Its prefrerred to have a single yaml file for whole pipeline

# Test Plans

We can create manual test cases and a tester can execute it here

Aslo we can have automated test in our pipline and result of which can be viewed here

We can also view the test from kanban board and run it from there

# Service Connections

Azure Devops need to connect and authenticate to other platforms in senerios like

- pushing docker image to some container repository
- deploying to remote server may be on some other azure tenant or aws
- in case code is hosted on some other external code repository
