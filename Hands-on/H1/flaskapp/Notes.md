In this we are just creating a basic production ready app https://www.youtube.com/watch?v=dVEjSmKFUVI

We will be creating 2 containers
- Flask
- Nginx

we can also use more like one for database and so on

So here in our case the request qill be coming from ngnix server container to our flask app container via uWSGI which is used as an application server

Nginx ----->WSGI----->Flask

WSGI - https://www.youtube.com/watch?v=8bCwDpsVYmE

# Build the app

- creating the virtual env

python -m venv env

- activate venv

source evv/scripts/activate

- install flask uwsgi (was havin trouble to run this, so decided to add all manually in requirements.txt)

- Next we create run.py which is our uWSGI file and entrypoint of our flask app

- We will then create new folder app which is our actual app

- in that we will create __init__.py and views.py

- then we will write both file and run.py

- Now we generate our requirements.txt

pip freeze > requirements.txt       (in my case i had problems installing lib so wrote manually)

- thn created .dockerignore file so that shit dosent goes in my image

- now we write our dockerfile for flask container image

- then we create app.ini which has a callable, so actualy nginx communicates with wsgi and it then calls the callable, in our case it is app being callable and is called by run.py which is uWSGI file


[uwsgi]
wsgi-file = run.py
callable = app
socket = :8080
processes = 4
threads = 2
master = true
die-on-term = true

uswgi will listen on port 8080 for any request

- next we create nginx.conf file which will have some custom configuration for nginx

now docker creates a docker network in docker-compose for containers to communicate freely
when we create container, the name of container itself becomes the hostname of it

- now we write dockerfile for nginx container image

- now we create our docker-compose.yml

- now we run our docker-compose

docker-compose build

docker-compose up

docker-compose up --build