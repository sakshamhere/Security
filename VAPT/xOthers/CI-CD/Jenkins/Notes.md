We are going to set up jenkins from scratch in a Docker container

1. Jenkins Container Setup 
2. Create multibranch pipeline with git repo
3. Types of Credentials\
4. Jenkinsfiles

*************************************************************************************************************************

Step 1 - is to run a jenkins image in a docker container

docker pull jenkins/jenkins or directly pull and run by docker run jenkins/jenkins

However before running it we need to specify some options like to open port so that we can access this from browser

How to run - https://github.com/jenkinsci/docker/blob/master/README.md

So first we bind port ie on port 8080, jenkins runs on 8080 because it runs on tomcat, and we are going to bind it to our host on port 8080

Another port we will expose is port 50000 where jenkins master and slave communicate, this will enable our jenkins to bind slave in case our have some

We are going to run it in -d detached mode, this is in background

Also we will create a named volume, we will specify host directory to be used as volume and map that to that exist in container

so overall command 

- docker run -p 8080:8080 -p 50000:50000 -d -v jenkins_home:/var/jenkins_home jenkins/jenkins:lts

Now we can see jenkins container running by docker ps

We now see its logs

- docker logs <container id>

We see 

"Jenkins initial setup is required. An admin user has been created and a password generated.
Please use the following password to proceed to installation:

2ee995df4e80474a984f863750eba154"

we go to localhost:8080 and paste this password

This will initialize jenkins and then we go with install suggested plugins

Usernam - jenkins-user
pass - majime
name - saksham doshi
email - sakshamdoshi101@gmail.com

Jenkins URL: http://localhost:8080/ (we continue with default ie localhost)

Go to "new item"

we can see diffrent type of project that we can create

Now there are following

1. Freestyle project - these are used for simple sngle tasks, like if we want to simply run test

2. Pipeline - with pipelne we can configure the whole delivery flow like test, build, package deploy etc

Pipline is a recent addition previouly they would just chain multiple freestyle project to achive what is done by pipeline

the pipeline is just for a "Single branch"

3. Multibranch Pipeline - this applies to multiple branch of same repository

* We here will use multibranch pipeline

Since we are admin we can go to Manage jenkin->manage plugin and see the installed and availible plugins

So lets type a name of pipeline in "new-item" and select multibranch pipeline

*************************************************************************************************************************

# Creating Pipelines

we can create pipeline in jenkins in 2 ways 

1. using plugin ie using UI
2. Using Groovy script

In Groovy script also we have 2 approaches 
1. Pipelie script or Scripted pipeline
2. Pipeline script from SCM or Declarative pipeline (Source Control Management)

1. Scripted -  In this we write the pipeline insoide the jenkins itself

2. Declarative Plugin
suppose we wrote grrovy script in some file which is called as Jenkinfile, that file will be there in some central repository along with the project, we can get that particular file and run that into jenkins

# Pipeline concepts for groovy script

below mention are keywords used in groovy script each represent some activity

1. Pipeline

This will create a pipeline

2. Node

This Node is on which the job runs, basically these are the agent as we have in azure devops

3. Stage

like build, test, deploy

4. Steps

stage contains multiple Steps

# Scripted pipeline

It is used when you only have a single jenkins server in your local machine

node{
    stage('Build'){
        // steps
    }
    stage('Test'){
        // steps
    }
    stage('Deploy'){
        // steps
    }
}


This we need to write in jenkins ui itself

in this when you are working with local machine acting as node  you dont need to write steps keyword you can directly 

node{                                              # this node reptesent here is local machine
    stage('Build'){
        
        echo "Building the project...."

    }
    stage('Test'){
        
        echo "Testing the project...."

    }
    stage('Deploy'){
        
        echo "Deploying the project...."

    }
  stage('Release'){
        
        echo "Releasing the project...."

    }
}

# Declarative Script

Now here we write the same code in a Jenkinsfile which has to be stored in some SCM repo ex gitgub

here we have diffrent syntex

Pipeline{
    agent any                       # every stage can have a or muultiple agent
    stages{
        stage('Build'){
            
            steps{
                //
            }

        }
        stage('Test'){
            when{
                expression{
                    BRANCH_NAME == 'dev'
                }
            }
            
            steps{
                //
            }
        }
        stage('Deploy'){
            
            steps{
                //
            }
        }
    stage('Release'){
            
            steps{
                //
            }
        }
    }
    post{
        always{
            // this is like finally in exception handelling as it will always execute whetehr build suceed of fails
        }
        success{
            // this is executed it build is success
        }
        faulure{
            // this will execute when build fails
        }
    }
}