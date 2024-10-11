# K8
H4
- mypod.yml Creating a single container in a pod
- multicontainerpod.yml creating pod with multicontainer

now when we exec into pod using 

    kubectl exec -it nginxwebserver bash

we see it automatically exec into container1 and not container2

we install netstat

    apt-get update && apt-get install net-tools

we do netstat -l or netstat -ntlp, we get the port at which container is litening, in this case its 80

we do ifconfig, we get ip 172.17.0.5

now we come out of container and exec into container 2, this time we mentioned -c flag so that we get into container2

kubectl exec -it nginxwebserver -c container2 sh (busybox dosent use bash so we use sh)

now here if we do 

wget 172.17.0.5

and cat index.html

* we see default entry page of nginx that means both containers can communicate freely in a pod

Aslo we if we do ifconfig in container 2 we see the same IP address

* In a Pod there can be multiple containers but IP address remains the samee

****************************************************************************************************************
- command and args

As we have ENTRYPOINT and CMD in Docker file we have command and args in k8

Dockerfile        k8        Description

ENTRYPOINT <----> command   Command that will be run by container

CMD        <----> args      Argument passed to container

the mains diffrence in ENTRYPOINT and CMD is that CMD can be overiided while run command while ENTRYPOINT cant

For example:-

if we see the busybox image, this image has CMD['sh'] in its dockerfile, so we can simply overwrite that


docker run -d --name busybox busybox sleep 3000

same thing we can do with "command " and "args" in yml file

as command ["sleep","3000"]

or

command:
 - sleep
 - "3000"

or also we can

command: ["sleep"]
args: ["3000"]

or simply

args ["sleep","3000"]


The resultant will be the combination of both command+args

CASE 1 - When we dont specify anything in k8 file then entrypoint and cmd of docker file is used

ENTRYPOINT      CMD         command(k8)     args(k8)        final result

sleep           3600            -               -              sleep 3000


CASE2 - If we specify command in k8 level then it will overite the entrypoint and cmd of image level

ENTRYPOINT      CMD         command(k8)         args(k8)        final result

sleep           3600       ping -c5 google.com    -              ping -c5 google.com        


CASE 3 - If we only have args specified at k8 level then entrypoint of image level will be used with it

ENTRYPOINT      CMD         command(k8)     args(k8)        final result

sleep           3600            -            5000              sleep 5000

CASE 4 - if we have both specified at k8 level then they will be used

ENTRYPOINT      CMD         command(k8)     args(k8)        final result

sleep           3600          ping          googl.com       ping google.com

******************************************************************************************************************
- understanding how port command of docker is similar to EXPOSE in docker

now in our mypod.yml we aff another field Ports

      ports:
        - containerPort: 8080  

now we apply and see kubectl describe pod , we see that it is litening at 8080

when we do kubectl explain pod.spec.containers , we see

ports        <[]Object>
     List of ports to expose from the container. Exposing a port here gives the
     system additional information about the network connections a container
     uses, but is primarily informational. Not specifying a port here DOES NOT
     prevent that port from being exposed. Any port which is listening on the
     default "0.0.0.0" address inside a container will be accessible from the
     network. Cannot be updated.
********************************************************************************************************************
- Understanding Labels and Selectors

we create three pod using cmd line

- kubectl run pod-1 --image=inginx
- kubectl run pod-2 --image=inginx
- kubectl run pod-3 --image=inginx

Now we do --show-labels

- kubectl get pods --show-labels

we see that by default there are labels 
run-pod1
run-pod2
run-pod3

with this kind of labels it is diffiult to identiy resources/objects so we give our own

- kubectl label pod pod-1 env=stage
- kubectl label pod pod-2 env=dev
- kubectl label pod pod-3 env=prod

now if you see these labels will be added

now if we see usecase of selector, so we can now use selector as kubectl get pods gives us all pods

kubectl get pods -l env=dev

now to remove a label we need to use command

kubect label pod pod-1 env-

now in case of production we make use of YAML files, in case of yaml files the labels are added in to metadata

we can see this the default label run by 

kubectl run nginx --image=nginx --dry-run=clinet -o yaml
************************************************************************************************************************
- understandin replicaset   

if we see in docs the replicaset comes into version apiversion v1

we simply copy and edit replicaset from https://kubernetes.io/docs/concepts/workloads/controllers/replicaset/

we see template in this - this template is simply  the configuration of pod ecculing the first two lines ie apiversion and kind

now we apply and see

kubectl apply -f replicaset.yaml
kubectl get replicaset

NAME       DESIRED   CURRENT   READY   AGE
frontend   3         3         3       5m9s

now as we know that replicaset tries achive desired state lets delete a pod 

kubectl delete pod frontend-2gks2 

and run get pods , we see it immediatly starts another pod

Note -  we see the labels assoiated with pods is same as selector in replicaset, because by that replicaset gets to know how many pods are runnning, and always label assigned in Template should be same as mentioned in selector in metadata of replicaset
********************************************************************************************************************
- understanding deployment and challanges with replicaset 

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

we can easily go through deployment rollout history and change deployment to previous version

- kubectl rollout history deployment.v1.apps/xyz

now similar to replicaset we create a deployment, we simlpy copy yaml of replicaset and change the name and kind of it

now we apply

kubectl apply deployment.yaml
    deployment.apps/my-deployment created

now if we see

kubectl get deployments

NAME            READY   UP-TO-DATE   AVAILABLE   AGE
my-deployment   3/3     3            3           38s

Now as deployment makes use of replicaset, we can also check

kubectl get replicaset

NAME                       DESIRED   CURRENT   READY   AGE
my-deployment-589c457889   3         3         3       88s

we can also see pods

So now these pods are managed by replicaset and replicaset is managed by Deployment

So now lets see roullout of new replicaset with deployment

lets update our image nginx to nginx:1.17.3 and apply deployment

- kubectl set image deployment my-deployment nginx=nginx:1.17.3 

now if we do kubectl get replicaset, we see two replicaset

NAME                       DESIRED   CURRENT   READY   AGE
my-deployment-589c457889   3         3         3       5m33s
my-deployment-58f5f96d7f   1         1         0       5s

So now the deployment will also start to remove the older version of replicaset

so now if do get replicaset again we see the older replicaset pods are removed

NAME                       DESIRED   CURRENT   READY   AGE
my-deployment-589c457889   0         0         0       7m52s
my-deployment-58f5f96d7f   3         3         3       2m24s


To see this in detail we can go to describe deployment and see the Event section

kubectl describe deployemt my-deployment

Events:
  Type    Reason             Age    From                   Message
  ----    ------             ----   ----                   -------
  Normal  ScalingReplicaSet  10m    deployment-controller  Scaled up replica set my-deployment-589c457889 to 3
  Normal  ScalingReplicaSet  5m6s   deployment-controller  Scaled up replica set my-deployment-58f5f96d7f to 1
  Normal  ScalingReplicaSet  3m17s  deployment-controller  Scaled down replica set my-deployment-589c457889 to 2
  Normal  ScalingReplicaSet  3m17s  deployment-controller  Scaled up replica set my-deployment-58f5f96d7f to 2
  Normal  ScalingReplicaSet  3m4s   deployment-controller  Scaled down replica set my-deployment-589c457889 to 1
  Normal  ScalingReplicaSet  3m4s   deployment-controller  Scaled up replica set my-deployment-58f5f96d7f to 3
  Normal  ScalingReplicaSet  2m52s  deployment-controller  Scaled down replica set my-deployment-589c457889 to 0

if we see clearly if scales up and down both simultenously

so now we see rollout history 

- kubectl rollout history deployment.apps/my-deployment

deployment.apps/my-deployment 
REVISION  CHANGE-CAUSE
1         <none>
2         <none>

now see the change -cause is none because we didnt use --record, use record to record command in change cause

- kubectl set image deployment <deployment name> <container name>=<container version> --record

we can also see the  changes by 

kubectl rollout history deployment.apps/my-deployment --revision 1
kubectl rollout history deployment.apps/my-deployment --revision 2

now lets see Rolling back

currently we asre in revision 2, now suppose we want to roll back toi revision 1

kubectl rollout undo deployment.apps/my-deployment --to-revision=1

now when do getreplicaset we can see the reverse ie the previuous revision is being rolled out

now if see version we see that we are on version 3 

deployment.apps/my-deployment 
REVISION  CHANGE-CAUSE
2         <none>
3         <none>

Creating deployment using CLI

kubectl create deployment <deploymnent name> --image=nginx
****************************************************************************************************************
# understanding Service

We will create a fontend pod which will request backend pod via backend gateway ie Service

* step 1 - create two backend containers

kubectl run backend-pod-1 --image=nginx
kubectl run backend-pod-2 --image=nginx

* step 2 - we create a frontend pod on ubuntu

kubectl run frontend-pod-1 --image=alpine --command -- sleep 3600

no we see using 

kubectl get pods -o wide

NAME             READY   STATUS    RESTARTS   AGE     IP           NODE       NOMINATED NODE   READINESS GATES
backend-pod-1    1/1     Running   0          10m     172.17.0.6   minikube   <none>           <none>
backend-pod-2    1/1     Running   0          9m53s   172.17.0.7   minikube   <none>           <none>
frontend-pod-1   1/1     Running   0          93s     172.17.0.3   minikube   <none>           <none>

* step 3 - test the connection between frontend and backend pod

we see all three pods are running on their unique IP

now lets try making a curl request from frontend to backend pod

lets get into frontend pod

Usually, an Alpine Linux image doesn't contain bash, Instead you can use /bin/ash, /bin/sh, ash or only sh.

kubectl exec -it frontend-pod-1 -- sh

we type curl and since curl is not present we do 

now in case of alpine the package manager is apk as we have apt in ubuntu

so we do 
apk update
apk add curl

now we will make a curl request a backend pod 1 172.17.0.6

curl 172.17.0.6

and as expected we recieve a html nginx response

* step 4- we create a Service

we create a service service.yaml

kubectl apply -f service.yaml

now if we do 

kubectl get service

NAME         TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)    AGE
kubernetes   ClusterIP   10.96.0.1        <none>        443/TCP    28d
myservice    ClusterIP   10.111.229.178   <none>        8080/TCP   80s

we see service by describe
kubectl describe service myservice

Name:              myservice
Namespace:         default
Labels:            <none>
Annotations:       <none>
Selector:          <none>
Type:              ClusterIP
IP Family Policy:  SingleStack
IP Families:       IPv4
IP:                10.111.229.178
IPs:               10.111.229.178
Port:              <unset>  8080/TCP
TargetPort:        80/TCP
Endpoints:         <none>
Session Affinity:  None
Events:            <none>

we see that the endpoint is none

so currently from frontend pod if we send request to this service this will not repond

if we do curl to service IP from frontend pod, we will not see any response

/ # curl 10.111.229.178:8080
curl: (7) Failed to connect to 10.111.229.178 port 80 after 21034 ms: Connection refused

* step 5 - connect/ Assosieate Endpoint with Service

so we create an endpoint.yaml

now if we apply it and see the desciption of service we can see the endpoint in it

Name:              myservice
Namespace:         default
Labels:            <none>
Annotations:       <none>
Selector:          <none>
Type:              ClusterIP
IP Family Policy:  SingleStack
IP Families:       IPv4
IP:                10.111.229.178
IPs:               10.111.229.178
Port:              <unset>  8080/TCP
TargetPort:        80/TCP
Endpoints:         172.17.0.6:80
Session Affinity:  None
Events:            <none>

now again we do curl from frontend pod to service, and this we can see the nginx response

    curl 10.111.229.178:8080

    ... ngninz html welocom page
*********************************************************************************************************************
- Intgrating Serice and Endpoint using Selector and label

NOW TILL NOW WE HAVE BEEN CREATING SERVICE AND ENDPOINT MANUALLY, we also specified ip address of backend pod in endpoint manually to redirect traffic to it

Though for one or two IP this aproach is fine but if there are 500 pods then we will have to add 500 ip address manully in endpoints which is not practial and scalable

hencc manual approach of adding ip addreess is avoid for production environmenrts

SOLUTION - In order to improve functionality k8 allows us the integration of Selectors with that of Services

So whenever we define a service we can specify that this should be redirect request to all pods with xyz label

* Step 1 - Creating deployment

so we will be creating a deployment mydeploymeny.yaml where in we have a replicaset and a template which obvioudsly has pod configuration

there we specify labels for pod and deployment, selector for replicaset so that it can select pod for replication

so we apply mydeployment.yaml

* step 2 - now we create a service myservice.yaml and make sure that selector has label assosited with our endpoint pod

so we apply myservice.yaml

* step 3 - verify the endpoints assosiated with our service

kubectl describe service myservice

Name:              myservice
Namespace:         default
Labels:            <none>
Annotations:       <none>
Selector:          app=nginx
Type:              ClusterIP
IP Family Policy:  SingleStack
IP Families:       IPv4
IP:                10.111.229.178
IPs:               10.111.229.178
Port:              <unset>  8080/TCP
TargetPort:        80/TCP
Endpoints:         172.17.0.3:80,172.17.0.6:80
Session Affinity:  None
Events:            <none>

we can see both the endpoints are now asosoiated with service

So now assume there is sudden rise in traffic on your website and you want more pods, so we scale pod from 2 to 4

kubectl scale deployment my-deployment --replicas=4

Now when we describe our service we see IP of all replicas in endpoints updated automatically , so we no longer need manual intervention

Name:              myservice
Namespace:         default
Labels:            <none>
Annotations:       <none>
Selector:          app=nginx
Type:              ClusterIP
IP Family Policy:  SingleStack
IP Families:       IPv4
IP:                10.111.229.178
IPs:               10.111.229.178
Port:              <unset>  8080/TCP
TargetPort:        80/TCP
Endpoints:         172.17.0.3:80,172.17.0.6:80,172.17.0.7:80 + 1 more...
Session Affinity:  None
Events:            <none>

we can also see list of of ip by

kubectl get endpoints

NAME         ENDPOINTS                                               AGE
kubernetes   192.168.49.2:8443                                       28d
myservice    172.17.0.3:80,172.17.0.6:80,172.17.0.7:80 + 1 more...   62m

kubectl describe endpoints myservice
*********************************************************************************************************************
- Understanding NodePort

NodePort exposes the Service on each Node's IP at a static port(NodePort)

we can cotact to  Node Pode Service from outside the cluster by requesting <workerIP>:<NodePort>

If service type is NodePort, then k8 will allocate a port(default:3000-32767) on every worker node

So till now we saw ClusterIP, but this can not be accessed by people outside cluster, so if any client outside wants to connect to nodeport service he will have to connect to public ip of worker node followed by a specific Port 

Step 1-  we will create a sample pod

kubectl run nodeport-pod --labels="type=publicpod" --image=nginx

kubectl get pods --show-labels

Step 2 - Create a Nodeport Service

the only diff will be that here we will specify type as nodeport, and put our pod label in selector

kubectl apply -f nodeportservice.yaml

now we go kubectl get service

NAME              TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)        AGE
kubernetes        ClusterIP   10.96.0.1        <none>        443/TCP        28d
myservice         ClusterIP   10.111.229.178   <none>        8080/TCP       172m
nodeportservice   NodePort    10.102.138.3     <none>        80:32488/TCP   46s

now here we can see 80:32488/TCP, so along with 80 we can also see port 32488, so if we want to connect to this nodeport service we have to get the ip address of workdernode followed by port 32488 like <workernodeIP>:32488

so lets do kubectl get nodes -o wide

NAME       STATUS   ROLES           AGE   VERSION   INTERNAL-IP    EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION                      CONTAINER-RUNTIME
minikube   Ready    control-plane   28d   v1.24.1   192.168.49.2   <none>        Ubuntu 20.04.4 LTS   5.10.16.3-microsoft-standard-WSL2   docker://20.10.17 

OOPs!!, so in our minikube we dont have any external ip, this can be perfomed in any other managed kubernetes service like aws, azure

so when we do <externalIP>:32488 in there case our request will be transfered to pod
*********************************************************************************************************************
- Challanges with NodePort, understanfin LoadBalancer service

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