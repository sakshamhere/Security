A big advantage of Gitlab to build Ci-CD pipeline is that you already have your code on Gitlab

Your team already works on Gitlab and you dont need a seperate platform for CI-CD pipeline

In jenkins we need to setup jenkins server then create a pipeline and then connect it to git project

while in Gitlab its seamless integration to code repository

# GitLab Architecture

1. Gitlab Instance or GitLab server -  host our application code and pipeline configuration basically the whole configuration, so it knows what needs to be done

2. Gilab Runners - Connected to gitlab instance are multiple runners which are actually the agents that run our pipeline

So Gitlab server assigns pipeline jobs to availible runners (runners here are just like agent in Azure devops)

Gitlab offers multiple runners which are managed by gitlab

We can set up complete self-managed gitlab and runners for our organisation

We will use gitlab managed infrastructure and free features

*************************************************************************************************************************

We are going to build a CI-CD pipeline for python application 

The whole pipeline will be wriiten as code in a file " .gitlab-ci.yml "

Gitlab can automatically detect the file and execute it

In Runner our commands run into a docker container




