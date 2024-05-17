In this we will deployment two applications mongodb and mongoexpress

we chose this two as they perfectly demonstrates web-app (mongo-express) and a database (mongodb)

First will create a mongodb pod deployment

Secondly to commnunicate with this pod we will need a service

we will create and INTERNAL SERVICE as we dont want any external request and only components in same cluster can talk to it

Then we will create a mongo-express pod deployment

we will need following
1. DB url of mongodb, so that mongoexpress can connect to it
2. Credentials, username and password, so that mongoexpress can authenicate 

The way we can pass these information to mongo-express is by its DEPLOYMENT configuration file through env variables

So we will create a CONFIGMAP that will contain DB Url

and we will create a SECRET that contains a credentials

we gonna refrence both configmap and secret in our mongo-express deployment configuration file

We then need mongo-express to be accessible through browser and so we will create and EXTERNAL SERVICE, this will allow external request to talk to pod

So it works like

Bowser request ----> External Service of mongoexpress -----> Mongo-express Pod ---> Internal Service of mongodb 

(configmap + secret)----------> mongodb Pod

***********************************************************************************

we create monodb deploymnent and leave value for username and pass balnk as we need to use secret , so before we apply configuration we create secret

the username and password in secret should be base64 encoded
we can do it by echo -n 'username' | base64

no we first need to apply mongodb-secret.yaml

kubectl apply -f mongodb-secret.yaml

now that we have created secret we can use them in our deployment file

now we can apply deploymnent for mongodb

Now we will create an Internal Service

**** WE CAN WRITE MULTIPLE DOCUMENT IN YAML

so if we start after --- (three dash)

so we can put both deployment and service in same file

So we create deployment for mongo-express using port and env variable

we will be using same secret in this 

we caneither use mongodb address or use configmap so that mulitple appliations can use external configuration

so we create a configmap file

just like secret the order of execution matters hence we first new to apply configmap

now we can apply mongo-express

now we want an external service so that we can access mongo-express from browser

we will create it in same deployment

# now to make it expternal we have to put TYPE:LOADBALANCER

this is what makes it external although internal service also acts a load balancer but they made it like that to dffer

one more thing we need to make external is is to put nodePort

# nodePort -it is the port where the external ip address will be opened
this port has to be between 30000-32767

since this is minikube, so in case we want to access this by browser of laptop we can run

kubectl service mongodb-express-service , and it will open in browser

