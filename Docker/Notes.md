Docker provides the ability to package and run an application in a loosely isolated environment called a container. 
It provides a viable, cost-effective alternative to hypervisor-based virtual machines, so you can use more of your compute capacity to achieve your business goals. 


- Develop your application and its supporting components using containers.
- The container becomes the unit for distributing and testing your application.
- When you’re ready, deploy your application into your production environment, as a container or an orchestrated service. This works the same whether your production environment is a local data center, a cloud provider, or a hybrid of the two.

Containers are great for continuous integration and continuous delivery (CI/CD) workflows.

Consider the following example scenario:
- Your developers write code locally and share their work with their colleagues using Docker containers.
- They use Docker to push their applications into a test environment and execute automated and manual tests.
- When developers find bugs, they can fix them in the development environment and redeploy them to the test environment for testing and validation.
- When testing is complete, getting the fix to the customer is as simple as pushing the updated image to the production environment.

Docker’s container-based platform allows for highly portable workloads. Docker containers can run on a developer’s local laptop, on physical or virtual machines in a data center, on cloud providers, or in a mixture of environments.

Docker’s portability and lightweight nature also make it easy to dynamically manage workloads, scaling up or tearing down applications and services as business needs dictate, in near real time.
***********************************************************************************************************************************************

Docker Architecture
- Docker uses a client-server architecture
- The DOCKER CLIENT talks to the DOCKER DAEMON, which does the heavy lifting of building, running, and distributing your Docker containers. 
- The Docker client and daemon can run on the same system
- you can also connect a Docker client to a remote Docker daemon
- The Docker client and daemon communicate using a REST API, over UNIX sockets or a network interface

DOCKER DAEMON (dockerd)  - listens for Docker API requests and manages Docker objects such as images, containers, networks, and volumes. A daemon can also communicate with other daemons to manage Docker services.

DOCKER CLIENT (docker)  - It is the primary way that many Docker users interact with Docker
                               When you use commands such as docker run, the client sends these commands to dockerd, which carries them out
                               The Docker client can communicate with more than one daemon.
        
DOCKER DESKTOP - Docker Desktop includes the Docker daemon (dockerd), the Docker client (docker), Docker COMPOSE, Docker CONTENT TRUST, KUBERNETES, and Credential Helper

DOCKER REGISTRIES - A Docker registry stores Docker images. Docker Hub is a public registry that anyone can use, and Docker is configured to look for images on Docker Hub by default. You can even run your own private registry.
                    When you use the docker pull or docker run commands, the required images are pulled from your configured registry. When you use the docker push command, your image is pushed to your configured registry.


************************************************************************************************************

Container is basically layer of image 
like there is a base image generally a linux alpine image above which there are application image like prostgresql etcx

---Diff bw Docker Image and Docker Container

Image is acutually an artifact which is portable while container is when such image is pulled and is running

so if its not running its image, while if run it on machine it is a container

---Diff bw docker and VM/virtualbox

Hardware -> OS kernel -> Applications

The docker virtualise at application level and uses the host kernel

the virtualbox / vm virtualise at os level and boots its own

Size - Therefore size of docker images are smaller because they just have to implement one layer
        thats docker images are of MB while vm images are of GB

Speed - docker are fast 

Compatiblity - VM of any OS can run on any os host but docker image cant

***************************************************************************************************************

Basic Docker commands

docker pull <image name>            (pull the image from registry ie dockerhub) (in case of private registry we need to specify complete registry name with image)

docker push <image name with require tag according to registry>

docker images                       (gives all the images)

docker run <image name>             (basically now you are crearing container from image, this run the image and pulls and run if not existing)
docker run <inmage name>:<version>

docker run -d <image name>          (detached mode - You can start a docker container in detached mode with a -d option. So the container starts up and run in background. That means, you start up the container and could use the console after startup for other commands.The opposite of detached mode is foreground mode. That is the default mode, when -d option is not used. In this mode, the console you are using to execute docker run will be attached to standard input, output and error. That means your console is attached to the container's process. 

docker logs -f <container_ID>/<name>.      (In detached mode, you can follow the standard output of your docker container )

Note when we run docker container it gives a random name but we can also specify of our choice

docker run -d <container_ID> --name mycontainer

docker ps                           (gives list of running containers)

docler ps                           (gives you all container which are running or not running)

docker stop <id of container>       (this will stop the container)

docker start <id of container>      (this will restart container)

docker exec -it <container id> -- bin/bash or sh (we can get the terminal of running container, may be we want to navigate in directory inside of virtual file system)

*************************************************************************************************************************

How to use Container?

# Port

So there is a port to which container listens for request

it might happen that two containers have same port but we need to bing them to different host them those host/localhost makes communication to our desired container 

we can bind this while run command 

docker run -p<laptop localhost port>:<container port>

***************************************************************************************************************************
Docker network

container within same docker network can communicate siply by ther name

we can create a network

docker network create <network name>

now while docker run we can specify this network to run two cantainer in same network

docker run -d -p<port>:<port> -e <any other env variable required> --name <your prferred name> --net <network name> <docker image>

***************************************************************************************************
Docker COMPOSE

 above we saw we can create a network where two container can talk just by name
 then we wrote run command with all the environment variables and other reuqred options set 

 * But this way of starting containers is obviously tedious, we dont want ot execute these run commands all the time on command line 

 there is a tool tha makes running multple container easier without running run command, that is docker COMPOSE

 docker compose is a .yaml file 

 we can take the whole commands and structure them in a file , you can write run command in structred way in docker compose

 there is no network configuration in compose, we dont have to create any network, docker compose will take care of that for container to communicate with each other

 How to use docker compose?

 docker-compose -f compose.yaml up -d    (we need to specify file (-f) and what we want to do that is here "up" that means start)

 now if we want to stop all containers, instead of "up" we will give "down"

 docker-compose -f compose.yaml down -d

A DOCKER COMPOSE FILE WILL BE USED ON DEV SERVER TO DEPLOY ALL APPLICATIONS

********************************************************************************************************************************************
So consider a senerio where you have developed application using frontend, backend and containers and now you want to deploy it.
To deploy your application it should be packaged into its own container

We are acutually gping to do what CI/ build pipleline or jenkins does ie how it packeges into artifact 

* DOCKERFILE

Docker file is a blueprint to create docker images

# BUILD AN Image

docker build -t <image name>:<image tag> <path/location of dockerfile>    (the -t is for name and tag, we can any of our choice)

# DELETE AN Image

docker rmi <image id>

# DELETE A Container

docker rm <container id>

# removes all stopped containers, dangling images, and unused networks:

docker system prune

********************************************************************************************************

DOCKER VOLUMES

this is used for data persistensce, so if we have databases or stateful applications we would use docker volumes

so a container is having a vritual file system, but if we stop the container the data is gone and it starts from fresh state next time

so how this works?

as we have a physical file system on host on which container runs, so we plug that with that of virtual file system of container

so wehen container writes on VFS it gets automatically written on host file system and vice versa

so when container starts it gets the data from the host file system

3 TYPES OF VOULUNES

1. HOST VOLUMES / BUILD MOUNT

docker run -v <host dicrectory>:<container directory>

2. Anonymous volumes

here in this we dont specify directiry of host where we need to map, it automatically gets created

docker run -v <container registry>

3. NAMED VOLUMES

this is simply improvised version of anonymous volumes where we have an option to specify name of folder on host file system

docker run -v name:<container directory>

If you use -v or --volume to bind-mount a file or directory that does not yet exist on the Docker host, -v creates the endpoint for you. It is always created as a directory.

If you use --mount to bind-mount a file or directory that does not yet exist on the Docker host, Docker does not automatically create it for you, but generates an error.

the one which should be used is Named Volumes

How to use or specify?

We simply need to specify this in docker compose 
**********************************************************************************************************************
# Copy files between localhost machine and running containers

docker cp <yourfoldername> <image name>:<path inside container>

ex - docker cp demo/. myimage:/test

this copies everything inside demo to test in container, if this test is not there it gets automatically created
**********************************************************************************************************************
# Managing Data in container using Volumes and Bind Mount 

There are two types of volume
1. Anonymous volume             (literally of no use as individial as folder mapped to host gets removed with container removal)

- Advantages

but these are useful with bind mounts to make sure the data copyied and installed by dockerfile is not overwritten when 
there are clash)

Since the anonymous volume is created and mnaged on hast machine which eventully gets removed with container, it helps to store data on host and improves perfoemance of container

2. Named Volumes (useful to persist data but we dont know where it is storing on our host)

- Cannot be create in a dockerfile but with run command

Advantage
- Save data accross container removals
- We can mount same named module to diffrent container and share data with other contaierns 

3. Bind Mounts

The bind mount are not managed by docker instead we set the path to which container folder can be mapped, here we are fully aware of the path of folder where is data is being mapped

Since once we make image and use COPY to copy all source code, futher changes after image being created are not reflected in our container as the image has taken snapshot using COPY command in dockerfile

but now using bind mount we can put that code in a folder and container can access that code from there, the container is no loinger dependent on COPY

so Bind mounts re perfect when we want editable persistence

* READ ONLY VOLUME
by default all three volumes have read-write access to the volume, that means docker can read and write to volume mapped to local host 

we can prevent that by putting a :ro after 

- docker run -v <path>:ro <imagename>

*********************************************************************************************************************
# Network Communications in Docker containerised app

Types of Communications

1. Container to WWW or internet
for example container wants to communicate to some API outside

2. Container to localhost Machine
for example container container wants to communcate some service running on our local host machine
for example database service

This is done by adding "host.docker.internal" in URL of service running on host

3. Container to Container
For exmaple app container wants to talk to sql/mongodb container


In Docker we can put multiple container into same network by putting --network command

all container can communicate with each other and IP gets resolved automatically

Two container are not able to talk unless you create a network or create a docker compose as in that case network is handled by docker itself




*********************************************************************************************************************
# Best Practises and Attack Surfaces for Container Security

The security of the container depends on correctly using the features and Isolation capabilities of an Operating System

The Contianer uses OS Virtualisation made possible by the capabilities of kernal of OS, which make a running application think that it has full copy of OS only to itself

# Summary of commands

- docker ps 

- docker ps -a

- docker images

- docker image inspect <image name>     (to see the configuration of image)

- docker pull <image name> 

- docker run <inmage name>:<version>             (basically now you are crearing container from image, this run the image and pulls and run if not existing)

- docker run -d <image name> 

- docker run -d --rm <image name>       (this will automatically remove the container from stopped container list)

- docker logs -f <container_ID>/<name>.      (In detached mode, you can follow the standard output of your docker container )

- docker run -d <container_ID> --name mycontainer

- docker run -p<laptop localhost port>:<container port>

- docker run -d -p<port>:<port> -e <any other env variable required> --name <your prferred name> --net <network name> <docker image>

- docker stop <id of container>

- docker exec -it <container id> -- bin/bash or sh (we can get the terminal of running container, may be we want to navigate in directory inside of virtual file system)

- docker-compose build

- docker-compose up

- docker-compose up --build

- docker-compose -f compose.yaml up -d    (we need to specify file (-f) and what we want to do that is here "up" that means start)

- docker-compose -f compose.yaml down -d

- docker build -t <image name>:<image tag> <path/location of dockerfile>    (the -t is for name and tag, we can any of our choice)

- docker rmi <image id>	# DELETE AN Image

- docker rm <container id>	# DELETE A Container

- docker system prune	# removes all stopped containers, dangling images, and unused networks:

- docker run -v <host dicrectory>:<container directory>	# HOST VOLUMES

- docker run -v name:<container directory>	#NAMED VOLUMES

- docker volume create <volume name> # Create named volume manually

- docker run -v absolute path:<container direcoery> # BIND MOUNT

- docker volume rm <volumename>         # remove volume    

- docker volume prune   # to get rid of unused volume

- docker push <image name with require tag according to registry>

- docker cp <yourfoldername> <image name>:<path inside container>

- docker volume ls      # to check volumes






