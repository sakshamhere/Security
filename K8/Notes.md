 ## Whats is Kubernetes?

Open Source Container orchestration tool, developed by google

Modern applications are increasingly built using containers, which are microservices packaged with their dependencies and configurations. 

Kubernetes (pronounced “koo-ber-net-ees”) is open-source software for deploying and managing those containers at scale

K8 helps us manage applications made of 100s and 1000s containers and in diffrent enviornment like cloud, hybrid etc

***************************************************************************************************

 ## WHY orchestration service?

The rise of microservices instead of monolithic architecture increased the use of container technologies

Container offers perfect host for small independent applications like microservices

now managing those containers by scripts can be really complex, this led the need for container orchestration

Container Orchestration can be used to perform:-

1. Provisioning and deployment of containers

2. Scaling up or removing container to spread application load evenly

3. Movement of container from one host to another if there is shortage of resources

4. Load balancing of service discovery between containers

5. Health monitoring of containers and host


****************************************************************************************************

## what k8/Container orchestration tool offers?

High Availaiblity - no downtime

High Scalability - loads fast

Disaster Recovery

******************************************************************************************************

Kubernetes Components

 ## Pod  - A very basic unit of K8

pod is an abstraction over container, it creates a running env or a layer on top of container so you only interact with
k8 layer not with container

Pod is generally meant to run one application per pod

How pod comminicate - so k8 offers a virtual network, so each pod gets its own IP address

Note - not the container its the pod who gets ip address

each pod can comminicate with its internal IP address 

Pods can die easily maybe bacause container application crashed and when that happens a new one gets created in its place and 
when that happens it will get assignes a new IP address which is inconvinent as now you have to adjust
because of this we have another componenent SERVICE 

## Service - it is a static/Permamnent IP address that can be assigned to each Pod

Lifecycle of pod and service are not connected so even if Pod dies service will be there

Since we need application to be accessed from public browser however we dont need such while communication with a database
therefore there are two types of service INTERNAL SERIVE AND EXTERNAL SERVICE, we can specify this when creating one

In case of EXTERNAL SERVICE the request first goes to another component INGRESS

# Ingress - used to route traffic in K8 cluster

So as pods uses service to commonicate, for example we need to communicate to a dabase service and we will have an endpoint/url of it usually this database url is in built of that application but if the name changes in SERVICE we would have to rebuild the container and push it again to repo and pull again in prod which is tedious

this is tedious for a change like database url for this we have component  CONFIGMAP

# ConfigMap - this will usually contain url of service and other configurations you use

we simply connect the pod to configmap so that pod gets data which configmap contains, we can simply make changes in configmap

now like URL we migh also have changes in username and password but this is confidential and con't be putted in ConfigMap
so for this we have another component SECRET

# Secret -  this is just like Configmap but is made for secret data like credentials and is not stored in plaintext but is encoed in base64


### Data Storage in Kubernetes

so for example we have pod which has database and it generates some data now if the database Pod/Container gets restarted the data would be gone , which is we dont never want

the way we solve this is VOLUMEs

# Volumes - it basically attaches a physical storage on harddrive to your Pod 

it could be on local machine on which pod is running or it can be outside of the cluster maybe cloud or on-prem storage

kubernetes does not manage data persistance hence we need to take care of it


Now if some case my application dies/crashes or we need to restart pod bewcause we build a new container image,
we will have downtime in which user wont be able to reach application

Threfore we replicate, we will have another server running pod using same SERVICE

Note - A Service is also acts as a Load Balancer

But in order to create a replica we wouldnt create a second Pod we instead define a Blueprint for our pod and specify how many REPLICA we want to run and that component is called DEPLOYMENT

# Deployment - Blueprint for pod

So we will not create Pod but we will create deployments and we specify no of replica and scale up or down

So Pod is a layer of abstraction on container and Deployment is another layer of abstraction on POD

We cant replicate Database pod with DELOYMENT because database has its state , all replica will access same Volume and there we will need some mechenism to avoid data inconsistency 

This mechenism is offered by another component called STATEFULSET

# StatefulSet

this component is specifically made for databases, so any stateful database like MySql, Mongobd should be created using StatefulSet not Deplouyments

it takes careds of replication and scaling

Note - Deploying databases using StatefulSet in k8 cluster can be tedious, it is difficult than Deplyment, therefore its common practise to host database outside kubernetes cluster and just stateless application or deplymenet in K8 

# DaemonSet

Replicas in a StatefulSet are scheduled and run across any available node in an AKS cluster.

For specific log collection or monitoring, you may need to run a pod on all, or selected, nodes,  DaemonSet Controller ensures that each node specified runs an instance of the pod.

Some typical uses of a DaemonSet are:

running a cluster storage daemon on every node
running a logs collection daemon on every node
running a node monitoring daemon on every node

Use a Deployment for stateless services, like frontends, where scaling up and down the number of replicas and rolling out updates are more important than controlling exactly which host the Pod runs on. Use a DaemonSet when it is important that a copy of a Pod always run on all or certain hosts


*************************************************************************************************************************

KUBERNETES ARCHITECTURE

In K8 the servers are called NODES

The Node will have multiple application PODS with Containers

## Worker Nodes / Nodes

Nodes are the service which actually do the work and are also called WorkerNodes

There are 3 process which needs to be there in every Node

1. Contaner runtime - the first thing node should have is container runtime it can be Docker or any other 

2. Kubelet - The Kubelet interacts with Container runtime and the machine which is Node

kublet is responsible for running a pod with container and assignining resources from node to that container

3. Kube Proxy - responsible for forwarding request from services to Pods, it has intelligent forwarding logic inside that makes sure communication works in a performant way with low overhead

We can 100s of those WORKER NODES / NODES which communicate by SERVICES

## Master Nodes - Controls Clustrer state and worker nodes

The question is how we interact with this cluster?
how to decide on which node new database pod will be scheduled?
if replica dies what monitors it and reschedule/restarts it?
when we add another server how does it join to become another node?
..and so on

the answer is, all these managing processess are done by master nodes

Master Node/servers have completely diffrent processess running inside

there are 4 main process running in master node 

1. API Server - So when you want to deploy a new application in k8 cluster you interact with API server using some client

the client can be UI/k8 dashboeard, it can be cmd line toll like KUBEctl or a kubernetes API

Kubectl is most powerful of all three clients

API server is like a cluster gateway which gets any intial request for updates and 

also acts as a gatekeeper for authentication making authenicated request gets to cluster

So whenver we want to deploy schedule new pods, deploy new appliocations or query status we need to talk to API Server - on Master Node

This is good as security point of view as we only have one Entrypoint

2. Scheduler

So if you send a request to API Server to schedule a pod API server will hand it over to Scheduler in order to start application node on one of the Node

Scheluder is intelligent to decide on which node next pod/cluster will be scheduled, it will see your request and resources required to run your application and check resource availibllity on each Worker Node and will schedule it where the worker node is less busy

Note - Scheduler simply decides on which node it should be scheduled, the process which actually starts that pod with container is the KUBELET

so Kubelet gets request from the Scheduler

3. Controller Manager

when pods dies Controller Manager detects that and tries to recover the cluster state as soon as possible and for that it makes request to Scheduler to re-schedule any pod and scheduler goes to Kubelet and same cycle discussed above starts

4. etcd (Cluster Brain)

its a key-value store of cluster state also called Cluster Brain 

whenever a new pod gets schedules or dies all these changes are saved in this key-value store etcd

So it is the one by which Controller mager knows pod died or started

it is the one by which scheduler knows which node is availlible 

it is the one which helps API server for queries like cluster health

all the cluster state information is stodred in etcd

In general K8 Cluster is made of Multiple Masters where API Server is Load balanced and etcd forms a distributed storage

*************************************************************************************************************************

# Minikube - 
single node k8 cluster that can run on our laptop like a virtualbox for testing k8 on local setup

Since we can test things process of workernode and master node on our local machine

for this use case there is this Opensource toll called minikube

this is basically a one Node k8 cluster where Master processess and workder node processess bothe runs and has Docker container runtime pre-installed

this runs on our laptop like a virtualbox


So now though you have minikube on local computer you neet to interact with it to create pod and other k8 components the way we do this is by Kubectl

# Kubectl

it is a command line tool for kubernetes cluster

# start a minikube cluster
minikube start
********************************************************************************************
## Basic Kubectl commands

- To get the nodes

kubectl get nodes

- To get the Pods

kubectl get pod

- To get the Services

kubectl get services

- To Create Kubernetes components

kubectl create .. (you can try kubectl create -h) (-h is for help)

you will observe you dont have pod in create help - because pod is something we create by Deployment

- To create Pod

kubectl create deployment NAME --image=image [--dry-run] [options]

We require image as pod needs to be made based on some container image

for ex = kubectl create deployment <anyname> --image=nginx (this will give us the deployment for latest nginx image from docker hub)



- To get deployments

kubectl get deployments

- To delete a deployment

kubectl delete deployment <deplyment name>


between Deployment and Pod there is REPLICASET which is automatically managed by kubernetes

Replicaset manages replica of pods

- To get Replicaset

kubectl get replicaset

we dont have to work with replicaset, we specify replica in blueprint ie the deployment

So the deployment manages -> replicaset, the replicaset manages -> Pods, the pods are abraction of -> Containers

Everything below managed by kebernetes

- To edit deployment

kubectl edit deployment <deployment name>

we get a file of deployment

once you edit and check pods, youll see old one will terminate and new one wil get running
also if you see the replicaset will have no pod in it and a new one is created

so you just edit deployment and everything gets updated on its own

# debuggin pods

another important command is kubectl logs which shows you what application running inside the pod has logged

kubectl logs <pod name>   (pod name will be like deploymentname-replicasetid-podid)


you can get information of pod status after deployment or when needed by

kubectl describe pod <pod name>

you can get the terminal of container abstracted by pod using

kubectl exec -it <pod name> -- bin/bash

# Kubernetes configuration file

so we see we need to specify name, image and other things in blueprint ie Create deployment command

like - create deployment <name> --image:image <option1> <option2> . ... ....

Although we can specify them but this is not practical to specify so many things on cmd line and so we have a configuration file 

so you provide all those things of component ie your blueprint in configuration file and execute it

you execute configuration file by

kubectl apply -f <filename> (.yaml file)

now if we want to change anything we can edit the file and apply again


****************************************************************************************
## Syntex of Configuration file 

The first two lines it just declaring what we want to create

Each Configuration file has three parts

1. metadata - the first part is the metadata of the component we are creating ex namer 

2. Specification - the second part is spec you want to apply to that component

These are the two main we configure other than that

3. Status - this is automatically generated and added by kubernetes, just like state in terraform

the k8 uses etd to create/update status

In case of pod we can see there is configuration of pod in a template in deployment
so it is like configuration inside a configiration

4. 1.1 Labels
5. 1.2 Selectors

We have Labels in metadata and Selectors in Specification 

# connecting deployment to pods
So in metada you give deployment or pod in a key value pair (ex app: nginx) 

so we create pods blueprint using this label and we tell the deployment to match all the labels (app:nginx) to create connection

this way deployment will know which pods belong to it

# connecting services to deployments
the deployment will have its own labels which will be used by service

6. ports

The service needs to know to which pod it should forward request and at which port it is listening ie *Targetport* which will refer ContainerPort
 

 **** WE CAN WRITE MULTIPLE DOCUMENT IN YAML

so if we start after --- (three dash)

so we can put both deployment and service in same file, because they belong together

***************************************************************************************************
## NAMESPACE IN K8

In Kubernetes we can organise resources in Namespaces so we can multiple namespaces in a cluster

We can think it is as a virtual cluster inside a kubernetes cluster

we can check for namespaces 

- kubectl get namepace (this will get all namspaces in cluster)

we get the following as default

1. kube-system - this namespace is not meant for our use, we shouldnt create or modify anything in kube-system, the components deployed in this namespace are the system processess

2. kube-public - this namspace conains publically accessible data, it contains a configmap which contains cluster information which is accessible without even authentication

3. kube-node-lease - this namespace is a recent addition to kubernetes, the purpose of this namespace it that it holds infoirmation about heartbeat of nodes, so each node has its lease object in namespace that contains its availiblity info

4. default - this is namespace which we use if we havent creates any namespace

we can create namespace

- kubectl create namespace <name> 

Another way is to create with configuration file

# What is the need of NAMESPACE and when and why should we use them??????

if we create everythin is single default namespace it will be very-unorganised and hence 

# (Structure/Organise components)
1. we should use this logical grouping using namepaces

# (Avoid Conflicts)
2. use-case - imagine 2 teams are working on same default namespace and one team overwrites deployment of another due to smae name of deployment and in case they use Jenkins or other CI-CD automation they wouldnt even know that they disrupted first teams deployment  

to avoid such conflict we can use namespaces like projectA namespace and ProjectB namespace

# (share services)
3. use case   - for example we want to host staging and development env in same cluster, reason for that is that if we are using ngnix-controller or elastic stack so we can deploy them in one clluster and can be used in both env

so we dont have to deploy these common resources twice in both deployments, staging and devlopment both can use same common service in cluster

for example we have two production versions which can use same resources in cluster

NOTE  - You cannot use any component of other namespace from one namespace, instead you should define same conponent within your namespace

However what you cans share is a service for ex mysql-service which is adatabase service

# (limit the acess)
4. use case   - as in use case 1 we saw two teams can diffrent namespace to work, so we can also limit those user by just providing access to just their namepsace and not the other 

in this way we minimize risk of one team accidently interfering another, making sure each team has their own isolated env

# (limit the resources)
5. usecase  - if a team uses more resources (CPU RAM STORAGE etc) then obviously there would be less for other teams so we can create Resource Quota per namepsace

According to documentation WE SHOULDNT USE NAMESPACES IF WE HAVE SMALLER PROJECTS UP TO 10 USERS

There are resource in k8 which cant be allocated to be any namespace and are globally unique like VOLUMES, NODES etc


# creating namespace
previously we created configfile in project demo and nowhere we added namespaace, by default it creates in default namespace

in any command that we use to check status we can use -n <namespcae-name> (which checks for namespace)
- kubectl get nodes -n <namespcae-name>
- kubectl get pod -n <namespcae-name>
- kubectl get services -n <namespcae-name>
- kubectl get deployments -n <namespcae-name>
- kubectl get replicaset -n <namespcae-name>
- kubectl get namespace -n <namespcae-name>

without namespace it is in default namespace so 

- kubectl get nodes ==  kubectl get nodes -n default

we can create conponent in any namespace using two ways

1. Using --namespace=<namespace name>

- kubectl apply -f <filename> (.yaml file) --namespace=<namespace name>

2. Defininfg the namespce in configuration file itself in metadata

It is preffred to use/define namespace in config file, as its ieasier to know where component is created by file

NOW for a team working in a namespace its very difficult to mention ( -n namespacename ) for every command

So in k8 as such there is no solution for this, but there is a toll "Kubens" which we can install

**********************************************************************************************
## INGRESS

So for any aplication its necessory to be accessible from browser or request from outside should be able to reach your application

One way to do this is by http protocol ip address and port using the EXTERNAL SERVICE

However this only good for testing and trying things fast, this is not the final product look (http:124.89.101.2:35010)

The final product should have a Secure connection ie HTTPS, a domain name like my-app.com (https://my-app.com)

The way to achive that using K8 component INGRESS 

so instead of external serviec we will have an internal service and will have a component ingress, ie we will not open our application through the IP address and port

So the request from the browser will go to Ingress and then to the Internal Service and then to Pod

In Ingress configuration file we define in Spec the routing rules in which we specify that any request to host my-app.com should get routed to Internal Service

We should map the domain to an entrypoing for example if we decide one of the node as entrypoint in cluster and map the domain host to the IP address of that node

So just creating the Ingress component isnt enough , in order to implement it we need Ingress Controller

## INGRESS CONTROLLER

Ingress Controller is just another pod or set of pod that run on a node in our cluster and performs evaluation and processing of ingress rules and managing redirection

it is important since you may have 50 or more ingress component in your cluster

So basically ingress controller will be the entrypoint in cluster for all request for all the domain or sub-domain rules that we configure

We need to choose any third-pary ingress conreoller, There is one from K8 itslef called

# ie K8 Nginx Ingress Controller

In a cloud provider it will be like

Cloud Load Balancer ---> Ingress Controller Pod ---> Ingress ---> Internal Service ---> app Pod

while in non-cloud you msy have a proxy server instead of load balancer

So in Conclustion none of your component in cluster is publically accessible which is good wrt sercurity


Lets see the Ingress controller (K8 Nginx Controller implementation) offered by Minikube 

# Congiguring https forwarding in Ingress

the only thing we need to do is define tls attribute in spec in configuration file with a secret name
which is a refrence to secret that you need to create that holds the tls certificate
*************************************************************************************************

## Helm

What is helm?

helm is a Package Manager for Kubernetes

it manages packaging yaml files and distruting them to public and private repositories

So for example we deployed Elastic Stack to collect logs of our application

now in order to deploy elsatic stack we will be needing a StatefulSet for databases, a Confimap, a Secret, a k8 user with respective permissions and couple of services

Now since using Elastic search is common thing, and making so many configurations in yaml files for it is a tedious thing, so there might be some place where all these files are availible for us to direclty use

an that ready to use bundle of yaml files is call HELM CHARTS

So using Helm we can create our own helm charts (bundle of yaml) and push it to some help reposiory to make it availible for others

Or we can consume / download existing helm charts that other might have contributed or pushed in reposiroties

So all services which require complex setup of yaml configurations of components, we can use availible helm charts in some repository

So now if you need some kind of deployment, you can simple search 

helm search <keyword>

you can also go to helm public repo ie " Helm Hub "

We can create private repo also for company use using some tools availible

Another usecase  ( Templating Engine )

Imagine you have an application that is made up of multiple microservices and you want to deploy all of them in your k8 cluster and deployment ans services are all same except you need diffrent image version or tags

so in this case without helm you will have to write seperate yaml files for each microservices with your small change

But using Helm you can define a common blueprint and that will be a TEMPLATE FILE

you will have a template file and instead of values you will have values.x which is taking values from an additional file Values.yaml

in Values.yaml we can define all those values which we want in all those yaml files

So instead of creating all those yaml files for a small channges we can do simply dynamically by a single template 

This is very practically useful in CI- CD as in build pipeline we can replace values dynamically before deploying


Another use case (Reusablity for diff env like prod test etc) - So if we want to deploy same application using all yaml files from staging env to prod we dont have to create them again

instead we can simply create out own Helm chart and use it to redeploy application in other env using one command

helm install <chart name>

The helm actually communicates with a Server in cluster called " Tiller "
Tiller keeps track of helm histroy of execution

sp you can make changes to alerady applied helm chart

helm upgrade <chart name>

So if in case some upgrage goes wrong, you can simply rollback the upgrage

helm rollback <chart name>

Since tiller had too much power to CRUD operations it was a security issue, due to this now in helm version 3 they removed tiller part and now only helm binary is there

***********************************************************************************************************
## VOLUMES

If in case we have an application pod creating data and updating in database pod.

By default when we restart the database pod, all those changes will be gone because k8 dosent give data persistence out of the box

this is something we need to configure to save data when pod restartds, basically we ned a storage which dosent depend on Pod lifecycle

Also we dont know on which node Pod is restarting so our storage should be availible on all Nodes, also we need something that survives even if cluster crashes

# PERSISTENT VOLUME - 

It is just like another cluster resource like CPU RAM used to store data

Just like any other component PV can be created using YAML file

PV makes use physical storage it can be either Local disk storage, remote Network file storage or Cloud storage

K8 gives you PV as an interface on which you need to maintain  and take care of storage

so we need to decide what type of storage we need and then create and manage by ourself

We can think os storage as an external plugin for cluster and we can have multiple

PV are independent of Namespaces and are accesible by whole cluster

K8 Administrator is reponsible to provision storrage and create Persistent Volumes from them based on information from developer teams

Developers has to explicitly configure yaml files to use Persistent Volume, in other words they need to Claim the Persistent Volume and we do that by another component called PERSISTENT VOLUME CLAIM

# PERSISTENT VOLUME CLAIM /PVC

PVCs are also created using YAML configuration

Both PVC and pod should be in same namespace

We need to use this PVC in our POD confiuration

So Pod request volumes using claim and claim then finds the volume, and in this way pod will now be able to use storage

So Admins need to provision storage and create PV and then developrs need to claim them 

In Case when many volumes are rewuired it can be tedious and time consuming to configure many storage and volumes 

So to make it easy there is another component called STORAGE CLASS

# STORAGE CLASS

Storage class provisions persistent volumes dynamically when PVC claims it, this way it is automated

Storage class are also created using YAML files

These SC are claimed by PVC and thus volumes are created dynamically

**********************************************************************************************
# Roles in k8

There are two main roles

1. K8 Administrator - who sets up cluster and maintains it and also make sure enouigh resources are availible, these are suallu devops engineers

2. k8 User - deployes application in cluster directly or through CI-CD pipeline, these are the developers in devops teanms

************************************************************************************************
## StatefulSet

Component that is used for stateful applications 

emaple can be any application that store data to keep track of state, mainly databases like mysql, elastic search, mongodb etc

# So Stateless applications are deployed using Deployment and Stateful applications are deployed using StatefulSet

they both manage pods on an identical container specification

we can configure storage for both in same way

So what is Diffrence? 
# Deployment VS StatefulSet

1. Replicating Stateful applications is difficult and have some other requirements while StatefulSet do not

For example there is java application pod replicas and using database pod replicas, so we can easily replicate and upscale or downscale using Deplyment component because replica pos are identical but the same cant be done for database pod because here the replica pod are not idential and they each have their own ientity

so maintaining this idenity is what statefulset does

The reason these have idenity is because in database pod replica not every pod can have both read and write permissions and so there is master slave thing to maintin database consistency

the pod who is allowed to update data is master while all others can only read and are called slaves

also they dont rely on same physical storage, instead master and slaves esch have their own and have to continiously synchronize thier data

We obvioiulsy use persistent storage for stateful application otherwise all data will be lost if cluster crashes

and the way to do is by configuring persistent volume PV for statefulset

when a pod dies the PV makes sure that the volume gets reattached to the pod by the help of uniique pod idenity

and this storage needs to be remote, because if pod gets destroyed on one node and reschedules to another the disk/volume storage wont be availibele in that another as local volumes are tied to specific node

2. Unline deployment which assignns pods a random hash, the StatefulSet gives each pod a fixed ordered name

also in statefulSet each pod has indivisdual DNS name which in deployment dont have

This means when the pod restarts the name and endpoint dns name remains same, so it gets a sticky identity

this sticky identity makes sure that pod gets its state and role even if it dies and reschedules

# Disadvantages of statefulSet

its very complex
we need to do a lot
- configuring the cloning and synchronisation
- making remote storage availible
- managing and backup

CONCLUSION

Stateful applications are not perfect for containerized enviornments



*********************************************************************************************************

# Securing Kubernetes

1.  Building A Secure image in CI-CD pipeline is the first step

- Code from Untrusted registries - we may be using a code or a library in our application which comes from an untrusted source, that might have some malwares or backdoors that can help attacker

- the base image which we are using may have some vulnerabilities

- We/developer should eliminate unnecessory dependencies / libraries while developing image

- One should choose smaller base images

* If the image is not secure the attacker can break out to the cluster host and do all the malpractises possible

* Image Scanning -  there are various tool that scan for vulnerabilities in image like Synk, Sysdig etc

they basically have a database of vulnerabilities that get updated regularly

we can do this scanning in CI CD pipeline just after the image is build before pushing it to repository

we should also scan images in repository as they might have vulnerability that might not have updated in scanner database

# *************************************************************************************************************

2. Avoid Using Root user in containers and running your containers with privilages

* If there is vulnerability in image and you are running it as root/privilaged acess then for attacker its very easy to perform Privilage Escalation

* So when building the image we should create a service user and run the application with that user instead of using root user

## We can overwrite to configure or misconfigure the pod to allow

spec:
  securityContext:
    rnaAsUser: 


spec:
  securityContext:
    allowPrivilageEscalation: true/false

we should avoid running images as privilaged user

Now onece above both steps are taken care our application is deployed and running in kubernetes, we have a number of things to secure inside the cluster itself

# ******************************************************************************************************************

3. Manage Users and Permissions in Kubernetes cluster and have least privilage 

we need to make sure the users have most restrictive permissions, in K8 we make sure this by RBAC

RBAC - Alows you to create roles with certain permissions

these roles need to be attached to users

In k8 There is no resource for creating user, instead users are indorectly created by either importing a list of users into our cluster or generating client certificate for API server for specific user

so client certificate will be registered for user and user for that certificate will be registered as user in k8 

once we have user with their clinet certificate assosiated with cluster we can attach those roles with specific users

We also have " Kubernetes Administrator" that needs to be able to create and update resources in multiple namespaces or anywhere in cluster and for that we have a resource "ClusterRole"

# ClusterRole (C.role) - Allows admin role

There are non-human users as well, like jenkins or any other tool that needs access to cluster so we need to provide them access as well

for non-human users there is a kubernets resource called " ServiceAccount "

# ServiceAccount (sa) 

The way this work is that every pod gets a ServiceAccount to talk to kubernetes

ServiceAccount just like human users has Roles assosiated to it with permissions

While users have clinet certificate to authenticate with APIserver, the ServiceAccount uses token to authenticate with APIserver

* It is important to limit permissions of ServiceAccount as if any attacker gains access to it, it can use tokens to authenticate to APIserver and do the malpractises

Now Using RBAC we can manage permissions for external users but what about inside the cluster itslef, the communication between services, by defeault each Pod can talk to any other pod

That means if an attacker gains access to any pod inside he can access any other application Pod

In Reality a Pod dosent need to talk all pod so we can Limit the communication by creating Network Rules that determines which pod can talk to which other pod and from which pod they can recieve traffic and we can do that with K8 resource " Network Policies "

# ********************************************************************************************************************
4. Define Communication rules between Pods

# Network Policies

Using this resource we can define like example a frontend pod can talk to backend pod but not to database service, we can define database pod traffic only from backend pod and so on..

So now even if attacker gets access to one pod they wont be able to any other pod of their interest 

these network policies in k8 are implemented by tools like weave etc    

Now this network policy will do this at network level but we can also do this at a service/application level using a " ServiceMesh " like Istio

# ServiceMesh

Istio uses proxies in each application pod that will control traffic coming in as well as traffice going out of application, we can configure rules that will be checked by istio

Another important thing is that by default the communication between pods in kubernetes is in plaintext / unencrypted

with ServiceMesh we can enable Mutual TLS / mTLS between pod so all the traffic will be encrypted

# ***************************************************************************************************************

5. Secure Secret Data

By default secret are stored unencrypted they are only base64 encoded so anyone who has permission to view secret can easily decode in plain text

We can use K8 own resource called " EncryptionConfiguration "

# EncryptionConfiguration

However we still ned to manage key and store it somewhere securely, 
so some third party tools can be used for this like
- AWS KMS service
- HashiCorp Vault

* So securing and encrypting Secret is important

# **********************************************************************************************************************

6. Securing etcd store

Secret and all other K8 components configuration data and every single change is stored in etcd, if attacker has access to etcd he can have unlimited access to cluster do all the mal practise

* It's a good practise to put your etcd behind firewall and whole data in etcd should be encrypted

# ***********************************************************************************************************************

7. Automated Backup & Restore

We should keep backup of our data and store backup safely so that it can be recovered when some uncertain happens

* " Kasten " is Kubernetes native data management Platform to configure backup and restore

Kasten transfers data securely, store data backup securely, encrypted data in rest in transit

attacker might be more advance enough that they might even corrupt your backup data, Swe need to protect those backups as well

" K10 " offers immutable backups which can't manipulated, it also provides automated recovery in any uncertain condition

# **********************************************************************************************************************

8. Configure Security Policies

We might be configuring everthing secure but the kubernetes is used by developers, so how do we ensure they follow these security best practises

Well for that we have
# Security Policies

security policies we can defeine rules such as

Pods that run with root user cannot be deployed
network policy needs to be defined for every pod and so on..

Secuirty policies in K8 are implemented by third party tools

************************************************************************************************************************
# Creating POD and Generating POD Manifest/yml by CLI

* Create a Pod

kubectl run [Name of Pod] --image=[image name]

kubectl run nginx --image=nginx

* Create a Pod and Exopse a port

kubectl run [Name of Pod] --image=[image name] --port=80

kubectl run nginx --image=nginx --port=80

* Generating Pod Manifest by CLI

kubectl run [Name of Pod] --image=[image name] --port=80 --dry-run=client 

when we do dry-run=client, this does not create pod in cluster, this is useful for testing

so we can generate yml manifest

kubectl run [Name of Pod] --image=[image name] --port=80 --dry-run=client -o yaml

kubectl run nginx --image=nginx --port=80 --dry-run=client -o yaml

This is very helpful as we can directly get yaml file and then edit it as per our need

*******************************************************************************************************************
# Summary
# To Summarize Components

- Worker Nodes
  - Container Runtime
  - Kubelet
  - Kube Proxy

- Master Nodes
  - API Server
  - Scheduler
  - Controller Manager
  - etcd
  
- Pod

- Service

- Ingress

- ConfigMap

- Secret

- Deployment

- StatefulSet

- Volume
  - Persistent Volume
  - PERSISTENT VOLUME CLAIM /PVC
  - STORAGE CLASS


# Other tools

- minikube - single node k8 cluster that can run on our laptop

- kubectl - command line tool for kubernetes cluster

- Ingress Controller - performs evaluation and processing of ingress rules and managing redirection

- Namespace - organise resources in Namespaces
  - kube-system
  - kube-public
  - kube-node-lease
  - default 

- Helm - Package Manager for Kubernetes
- Roles - 
  - K8 Administrator
  - K8 user

# #######################################################################################################################

# To Summarize commands

## common commands of K8 components

- kubectl create namespace <name>
- kubectl apply -f <filename> (.yaml file)
- kubectl apply -f <filename> (.yaml file) --namespace=<namespace name>
- kubectl get <component name> / <shrotname>
- kubectl get <component name> / <shrotname> -o wide
- kubectl get all
- kubectl get <component name> -n <namespace name>
- kubectl get all -n <namespace name>
- kubectl describe <component type> <component name>
- kubectl logs <component name>
- kubectl delete <component type> <component name>
- kubectl delete <component type> --all

## debug commands

- kubectl exec -it <pod name> -- bin/bash
- kubectl exec -it nginxwebserver -c container2 sh    (as in multicontainer pod, as by default container 1 is chosen)

# Creating and Manifest/yml by CLI

- kubectl run [Name of Pod] --image=[image name]
- kubectl run [Name of Pod] --image=[image name] --port=80
- kubectl run [Name of Pod] --image=[image name] --port 80 --dry-run=client
- kubectl run [Name of Pod] --image=[image name] --port=80 --dry-run=client -o yaml
- kubectl run [Name of Pod] --image=[image name] --port=80 --dry-run=client -o yaml > filaname.yaml

- kubectl create deployment [name of deployment] --image=[image name]
- kubectl create deployment [name of deployment] --image=[image name] --replicas <number of replica>
- kubectl create deployment [name of deployment] --image=[image name] --dry-run=client -o yaml > filaname.yaml

- kubectl expose pod [pod name] --name [service name] --port=80 --target-port=80 --dry-run=client -o yaml
- kubectl expose pod [deployment name] --name [service name] --port=80 --target-port=80 --dry-run=client -o yaml
- kubectl expose pod [pod name] --name [service name] --port=80 --target-port=80 --dry-run=client -o yaml --type=NodePort

# Commands for labels and Selectors
- kubectl get <component> --show-labels
- kubectl label <component> <component name> <label key>=<label value>      (adding label)
- kubectl label <component> --all <label key>=<label value>  (adding a label to all particular component in a namespace)
- kubectl label <component> <pod name> <label key>-                   (removing label)
- kubectl get <component> -l <label key>=<label value>               (using selector)

# Commands for deployment 
- kubectl set image deployment <deployment name> <container name>=<container version> --record    (Set new Image)
- kubectl scale deployment <deployment name> --replicas <number of replica>                       (Scale deployemt)
- kubectl edit deployment <deployment name>
- kubectl rollout history deployment.apps/<deployment name>
- kubectl rollout history deployment.apps/<deployment name> --revision <revision number>
- kubectl rollout undo deployment.apps/<deployment name> --to-revision=<revision number>           (rollout undo)

# Helm chart

- helm search <keyword>
- helm install <chart name>
- helm upgrade <chart name>
- helm rollback <chart name>


# #######################################################################################################################

# Best Security practises inside k8

1. Building A Secure image in CI-CD pipeline is the first step

2. Avoid Using Root user in containers and running your containers with privilages

3. Manage Users and Permissions in Kubernetes cluster and have least privilage 

4. Nework Policies using ServiceMesh and Istio - Define Communication rules between Pods

5. Secure Secret Data

6. Securing etcd store

7. Automated Backup & Restore

8. Configure Security Policies

9. looging by serivices like Prometheus, Splunk

**********************************************************************************************************************

# kubeconfig Files

Note - A file that is used to configure access to clusters is called a kubeconfig file. 
This is a generic way of referring to configuration files. It does not mean that there is a file named kubeconfig.

By default, kubectl looks for a file named config in the $HOME/.kube directory. You can specify other kubeconfig files by setting the KUBECONFIG environment variable or by setting the --kubeconfig flag.

Suppose you have several clusters, and your users and components authenticate in a variety of ways. For example:

A running kubelet might authenticate using certificates.
A user might authenticate using tokens.
Administrators might have sets of certificates that they provide to individual users.

With kubeconfig files, you can organize your clusters, users, and namespaces. You can also define contexts to quickly and easily switch between clusters and namespaces.

You switch between clusters using the kubectl config use-context command.

****************************************************************************************************************
# Dockerfile vs K8 

As we have ENTRYPOINT and CMD in Docker file we have command and args in k8

Dockerfile        k8        Description

ENTRYPOINT <----> command   Command that will be run by container

CMD        <----> args      Argument passed to container

the mains diffrence in ENTRYPOINT and CMD is that CMD can be overiided while run command while ENTRYPOINT cant

************************************************************************************************************
# Labels and Selectors

- Labels

for example we have resources like Server, Database and Load Balancer each for two diffrent enviormenet

now in such case if we are asked to stop all servers of Dev env then it will be difficult for us to find which belongs to dev env as there are no albels assosiated to them

Labels are similar to Tags the one we configure while creating/provisioning Azure or AWS resource

Labels are nothing but a key-value pair to uniquily identify resource 

- Selectors

So selectors basically allows us to filter objects based on labels

for Example - show me all the k8 objects where label is env:prod  

We can use selectors on label like

kubectl get pods -l env=dev
********************************************************************************************************************
# Replicaset

Replicaset purpose is to maintain a set of replica pods running at any given time
In replicaset we have 2 configuration

1. desired state 
2. Image
so if 
desired state=3
image=nginx

So it will maintain 3 pods of image at any given time

Now there is another term Current state so 

Desired State - is the actual state of pod which is desired
Current State - is the actual state of pod which is running

So in case if any pod exits/stops the current state will no become 2 and Replicaset will try to make the value of current state 3 by creating new pod

if we see in docs the replicaset comes into version apiversion v1

we simply copy and edit replicaset from https://kubernetes.io/docs/concepts/workloads/controllers/replicaset/

we see template in this - this template is simply  the configuration of pod ecculing the first two lines ie apiversion and kind

Note -  we see the labels assoiated with pods is same as selector in replicaset, because by that replicaset gets to know how many pods are runnning, and always label assigned in Template should be same as mentioned in selector in metadata of replicaset
********************************************************************************************************************
# Deployment

Now in replicaset we get basi c functionality of managing and scaling pods

Now if we want additional capabilites like rolling out changes and rolling back changes, we use deployment

Now deployment makes use of replicaset to achieve the replication capability for pods, along with this it also able to performs various other things

Benifits of deployment

1. Rolling out changes

for example you are in need to deploy a new version of application, so in this case deployment will proviion new replicaset with new version in parallel to lod replicaset and once new verion starts running, it will remove older version

This makes sure the application is never going down

deployment ensures only a certain amount of pods are down while application is updated and it scales up new version scales down new version silmulteneouly

by default it ensures atleat 25% of pods are up

it also keeps history of revisions of new deployment

2. Rollback of changes

for example you rolled new application and now dues to some issue its not perfoirmning well for users so now you would like to roll back to previous version which was working perfectly, this can be done by deployment
*********************************************************************************************************************
# DaemonSets

Lets assume a case where we want to run a single copy of pod in each node 

Now if we simply create replicaset and use then it might create 2 pod in a single node based on its resource availiblity 

in order to achieve this we use DaemonSet

There can be many usecase in which we may require DaemonSet for example

1. Antivirus - So we might want an antivirus pod which scans regularly Node for malicious activities, in such case we would only want single pod in each node for antivirusa

we also may want to ensure that whenever a new Node is provisioned it has to include one antivirus pod
*******************************************************************************************************************
# NodeSelector

nodeSelector allows us to add a constraint about running a pod in a specific node

For example
- App A requires faster disk or in nodes which has SSD in order to be able to run effectively

etc..

Now like other objects Nodes can also be assigend labels, like disk:ssd or disk:HDD 

and similar to selector a nodeselector select node on the basis of labels

by default node has some labels and we can assign too

- kubectl label node minikube disk=ssd

then we can see by describe node

Labels:             beta.kubernetes.io/arch=amd64
                    beta.kubernetes.io/os=linux
                    disk=ssd
                    kubernetes.io/arch=amd64
                    kubernetes.io/hostname=minikube
                    kubernetes.io/os=linux
                    minikube.k8s.io/commit=f4b412861bb746be73053c9f6d2895f12cf78565
                    minikube.k8s.io/name=minikube
                    minikube.k8s.io/primary=true
                    minikube.k8s.io/updated_at=2022_07_04T09_59_57_0700
                    minikube.k8s.io/version=v1.26.0
                    node-role.kubernetes.io/control-plane=
                    node.kubernetes.io/exclude-from-external-load-balancers=

now in order to make sure the pod runs on that particular node only, we add nodeSelector in spec
************************************************************************************************************************
# Node affinity

Node affinity is a set of rules used by scheduler to determine where a pod should be placed

in K8 we can achive this node affinity by 

1. NodeSelector
2. nodeAffinity (more flexiblity)

Soon nodeAffnity will take over and Nodeselector will be deprecated, it is similar and allow us to constrain which node our pod is eligible using labels


now, nodeaffinity basically contains 2 important parts

1. requiredDuringSchedulingIgnoreDuringExecution    -> Hard preference

This is hard requirement, and has to be filled, if it dosent find node availible with label key value it wont schedule pod

apiVersion: v1
kind: Pod
metadata:
  name: with-node-affinity
spec:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: topology.kubernetes.io/zone      # this is key of label of node
            operator: In                          # this is like in , not in etc
            values:                               # this is value of label of node
            - antarctica-east1
            - antarctica-west1

2. preferredDuringSchedulingIgnoreDuringExecution   -> Soft prefrenece

This will simply prefer if that node is availibel, otherwise will schedule on some other pod which does not have labels key value we mention

     preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 1
        preference:
          matchExpressions:
          - key: another-node-label-key
            operator: In
            values:
            - another-node-label-value
*********************************************************************************************************************
# Resource Limits
* Request
* Limits

Request and Limits are two ways in which we control the amount of resource that can be assigned to a pod.

Request: by this pod is guranteed to get specific resource defined
Limits:  this make sure that container does not take node resources above a specific value


apiVersion: v1
kind: Pod
metadata:
  name: nginxwebserver
  labels:
    env: dev
spec:
  containers:
    - image: nginx
      name: democontainer
      resources:
        request:
          memory: "64Mi"
          cpu: "0.5"
        limits:
          memory: "128Mi"
          cpu: "1"

The Schedular schedules pod based on request parameters, while limits are only considered post scheduling
*********************************************************************************************************************
# Taints and Tolerations


so taint is like a boundry, when a taint is applied to a node the pod is not allowed to be scheduled on it

now in order to pod to enter that boundry ie to be scheduled on a tainted pod it needs a special pass which is called toleration

so if a pod is trying  to be scheduled on a tainted node and also has toleration then it will be allowed to be scheduled on it

we can apply taint by

kubectl taint nodes <node name> key=value:<anythhing>

For example,

- kubectl taint nodes node1 key1=value1:NoSchedule

now if you do kubectl describe you can see node is tainted

so in order to pod to be allowed to scheduled on tainted node, we will add tolrations

the toleration is addedd in spec of pod

for ex in below deployment

apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
  labels:
    app: guestbook
    tier: frontend
spec:
  replicas: 3
  selector:
    matchLabels:
      tier: frontend
  template:       
    metadata:
      labels:
        tier: frontend
    spec:
      containers:
      - name: nginx
        image: nginx:1.17.3
      tolerations:
      - key: "key1"
        operator: "Exist"
        effect: "NoSchedule"

- Comnponents of Taints and Tolerations

1. Key  = this can be any string upto 253 characters

2. value  = this can be any string upto 253 characters

2. Effect
there are three effect

- NoSchedule

This means new pods that do not match the taint (means having toleration for that taint) are not scheduled on that node

However exitsting pod remains on it as it is

- PreferNoSchedule

In this schedular tries not to schedule new pod without taint but might get scheduled on that node 

However exitsting pod remains on it as it is

- NoExecute

This means new pods that do not match the taint (means having toleration for that taint) are not scheduled on that node

Aslo exitsting pod that do not match taint ie not having required tolerations are removed from node

3. Operator

- Equal

This is the default operator, in this the key/value/effect parameters must match

- Exist

In this the key/effect parameters must match and you must leave a blank value which matches any
******************************************************************************************************************
# Service

* UseCase 1
Consider a case where in Worker node1 there are two pods Fronted and Backend both have thier ip

Now in order for frontend to connect to backend it will ip address of it

if we assume that we have specified this ip in frontend configuration to communicate with backend, so now everytime frontend will refer that configuration to communicate with backend

Now if in case the backed app stopped working due to some issue, so in this case deployment will launch new pod which wuill have a new ip address

So now frontend is still refrencing old ip of stopped pod and it will start showing error like http 500 to users

* UseCase2

Now consider a case where in we have multiple replica of backend pod, in this case how will we update configuration file of frontent for IP and dns stuff

Solution
So in order to overcome both of the issues we saw above we make use of kubernetes Services

So Services will act like a backend gateway between frontend and backend pod or replicas of backend pods, as frontend will now only refer this Service which is assosited with all backnd pods

and since this refernce to service is mentioned in our pod configuration hence if any new backend pod is created it can also be directly assosiated to service and be accessbed by fronted

This service also acts as a load balancer

There are several type of services availible
* NodePort
* ClusterIP
* LoadBalancer
* ExternalName
*******************************************************************************************************************
# ClusterIP Service

When a Service is ClusterIP, an internal cluster IP is assigned to it, and since it it internal IP it can only be reachable from within the cluster

this is default ServiceType, so we create a service and dont define a type it will be clusterIP
********************************************************************************************************************
# NodePort Service

NodePort exposes the Service on each Node's IP at a static port(NodePort)

we can cotact to  Node Pode Service from outside the cluster by requesting <workerIP>:<NodePort>

If service type is NodePort, then k8 will allocate a port(default:3000-32767) on every worker node

So till now we saw ClusterIP, but this can not be accessed by people outside cluster, so if any client outside wants to connect to nodeport service he will have to connect to public ip of worker node followed by a specific Port 
*********************************************************************************************************************
# LoadBalacer Service

LoadBalancer basically makes use of NodePort as part of its overall integration

Now the challanges with NodePort service is that whenever we want to open our application, always we have to specify the IP address of workernode followed by NodePort, So this is something not suitable for production enviornment

To overcome this we have LoadBalancer service, 

So in loadbalancer service type a new external loadbalancer gets created automatically and then this loadbalancer takes care of routing request to underlying service

Client ------> Load Balancer ----------->nodeport(35252) ------->nodeport service -------> Pod

In this we could have performed practical if using managed kubernetes service like aws, azure or digital ocean

So the service only has diffrence in its type as in loadbalancerservice.yaml

step 1 - we crete a sample pod

kubectl run lb-pod --labels="type=loadbalanced" --image=nginx

step 2 - create a service and apply

kubectl apply -f loadbalancerservice.yaml

Now after applying we can see a new external load balancer gets created in Cloud Provider and is automatically integrated with nodeport

when we paster the punlic ip of external loadbalamcer in browser we get our ngin welocome page of pod

in case of cloud provider, in case of managed kubernetes service the integration s automatic as we saw above, ie external loadbalancer is created automatically

in case of bare metal env we have to create it on own
************************************************************************************************************************
# Ingress & Ingress controller

Now the LoadBalancer service makes use of external load balancer which is actually a layer 4 load balancer

now the challange is that layer 4 lb works simply by reverse proxying data to availible server, without knowing data
beacuse it can only see an IP adress and port based on which it routes traffic

https://www.youtube.com/watch?v=aKMLgFVxZYk, https://www.youtube.com/watch?v=ozhe__GdWC8

now suppose we have multiple application pod running app.com, xyzapp.in etc  using diffrent services, these can also be in completely diffrent env in same cluster

                        |     <example-service> ----->  POD
Client ---->  LB --->   |       example.com
                        |
                        |     <kplabs-service>  ----->  Pod
                                kplabs.in


Now for example user types example.com then request should be reouted to example-service and then to pod and same for kplabs.in

But this is something cant be achieeved by a Layer 4 Load balancer, and to achive it we would need sepearete load labalncer for multiple website in cluster

Challanges
prising - using multiple load balancer will give huge cost and complexity as well

The External load balancer is layer 4 lb so it cant see header or any sort of data it simply routes traffic

These capababilites are achived by layer 7 load balancer

SOLUTION
So in K8 there is an intermediate gateway which has intellence  to do a layer 7 load balancing here

so now the client will send request to External Load Balancer which will then send this to this Gateway

This gateway will have rule set by us by which request will be directed to required Service for pod

This intelligent gateway working as layer 7 load balancer is called INGRESS

                        |I
                        |N         <example-service> ----->  POD
Client ---->  LB --->   |G           example.com
                        |R
                        |E         <kplabs-service>  ----->  Pod
                        |S        kplabs.in
                        |S

Ingress provides features like
- LoadBalancing
- SSL Termination
- Named based virtual hosting

Now There are two sub-components when we talk about Ingress

1. Ingress Resource / Rules
2. Ingress Controllers

Ingress Resource - basically contains a set of routing rules based on which traffic is routed to a specif service

Ingress Controller - It takes care of implementing the ingress resource ie the rules

Note - You must have an Ingress controller to satify ingress resource/rules. Only creating ingress resource has no use

There are varioud Ingress controller availible we can use it on our requirement - https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/


Ingress controller makes use of LoadBalancer type service, So When using Managed Kubernetes , when we create Ingress controller it will automatically create the external load balancer and will forward traffic to port of itself

