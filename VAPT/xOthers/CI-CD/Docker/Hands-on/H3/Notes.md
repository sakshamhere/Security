We dockerise the node app

1. we write the dockerfile

2. we build the image

docker build -t feedback-node .

(when we dont specify any tag by default latest tag is assigned)

3. now we run our image

- we run it on port 3000
- we run it in detached mode
- we also give it a name
- we make sure it gets removed by --rm

docker run -p 3000:80 -d --name feedback-app --rm feedback-node

4. app runs at http://127.0.0.1:3000/

5. Now when we write title in form and save

suppose we enter title as "newtitle" and document text as "awesome"

- this app basically converts the title into a file, also we can access it http://127.0.0.1:3000/feedback/newtitle.txt

Now the thing to observe here is this file is not in our laptop feedback folder but instead in our container

The reason is because we copied all folder including feedback in container while building, but then container has its own isolated file system 

there is no connection in our local and container file system

But now if we stop the container and rerun it the above file http://127.0.0.1:3000/feedback/newtitle.txt dosent exist !!

this is because we also removed the container by --rm

but if we start container without --rm and stop and start it again, we notice the file still there

so the file was lost not because we stopped the container but because we removed the container

But thats the problem, we want to stay these files even if remove/delete the contaners, we might want to make changes to our code and then rebuild image and start container and access those files 

Solution to problem is 
# VOLUMES
volumes helps to persist data in docker

Volumes  - volumes are folder on your host machines ie your computer which you make docker aware of and which are then mapped to folder inside the container

so if you add a file in mapped host machine it is accessible folder inside container and similarly any changes made inside container are refelected in host machine folder

# How to add volume

one way is to add VOLUME in our dockerfile

we write
VOLUME ["path inside container"]

in our case
VOLUME [ "/app/feedback" ]

we dont mentione the path of our host machine

we then build this image, this time with volumes tag

docker build -t feedback-node:volumes .

now lets run this container image

docker run -d -p 3000:80 --name feedback-app --rm feedback-node:volumes

when we save form we get an error because we need to change code in server.js

put 
      await fs.copyFile(tempFilePath,finalFilePath)
      await fs.unlink(tempFilePath)

now remove image and rebiuld and rerun

still we wont be able to accees file if container is removed because this is Anonynomus volume

# Anonymous volume
Because this is anonymous volumes which gets removed when container is removed  and nothing is mapped to host machine hence of no use to our problem

now lets look at Named Volumes
# Named Volumes
So in this the data is mapped to some folder in host machine BUT we dont know where and we cant access it directly

but yes the data now persist somewhere and can be recovered even id container is removed

NAmed volumes are great which should be persistent but which you dont need to edit or view directly

the mapped volume is somewhere managed by docker on your host machine which you cant find easily

* we cant create Named Volumes by docker files

hence we remove it from our dockerfile and rebuild the image

docker build -t feedback-node:volumes .

NOW IMPORTANT thing

so we dont specify named volume in dockerfiles, we do it while we run image by -v flag

we can specify a name of our choice by which volume will be stored on our host machine and map it to that of container

docker run -d --rm -p 3000:80 --name feedback-app -v <name of our choice>:<path in container> feedback-node:volumes

in our case

docker run -d --rm -p 3000:80 --name feedback-app -v feedback:/app/feedback feedback-node:volumes

The key diff here from anonymous volumes is that named volume will not be deleted even if contaier shuts down/deleted/removed

those anonymous are of no use because they are recreated with container

so now we run
docker run -d --rm -p 3000:80 --name feedback-app -v feedback:/app/feedback feedback-node:volumes

and enter "title" and "demo txt" and then delete the container, here stopping will delete as --rm is there

then we check volumes

docker volume ls

we see our feedback volume even after container being removed

we can cross check by restarting container and accessing thsat file

# Bind Mounts

The bind mount are not managed by docker instead we set the path to which container folder can be mapped, here we are fully aware of the path of folder where is data is being mapped

Since once we make image and use COPY to copy all source code, futher changes after image being created are not reflected in our container as the image has taken snapshot using COPY command in dockerfile

but now using bind mount we can put that code in a folder and container can access that code from there, the container is no loinger dependent on COPY

so Bind mounts re perfect when we want editable persistence

* we create bind mounts like named volumes but instead we provide exact path

so we will add another -v in our previous command

docker run -d --rm -p 3000:80 --name feedback-app -v feedback:/app/feedback -v C:\Users\Lenovo\Desktop\Dev-ops\Hands-on\H3\Node-app:app feedback-node:volumes

here we mapped our whole folder of source code

Note - we should make sure docker has access to folder which we are making as bind mount 

Go to Docker->resources and check the parent folder is there

(in windows there is no problem)

But when we run this the app crashes becase by using this volume we overwrite all the things we did like RUN COPY etc in dockrfile, we lost our dependenciues which we installed and we simply have our source code folder that container is accessing now not the dependencies which should be there as we never put them in our source code fodler

This is solved when we add a Anonymous Volume to our node_modelus so when there is clash the longer internal path wins

Note- we can add anonymous vulumes in command line also

docker run -d -p 3000:80 --rm --name feedback-app -v feedback:/app/feedback -v "C:\Users\Lenovo\Desktop\Dev-ops\Hands-on\H3\Node-app":app -v /app/node_modules feedback-node:volumes

This is not working, but this is how we do it, now changing source code will also reflect in running container