https://www.youtube.com/watch?v=vb7w7jnkD2s

1. creating a virtual env and activate it

python -m venv env

2. create app.y and install flask lib

pip install flask
pip list

3. then try running app in debug mode

python app.py

4. now ill generate the requirements.txt

pip freeze > requirements.txt

4. now ill create my dockerfile

5. since i wrote to copy all files in image so ill also include dockerignore

6. now ill build my image and name it flaskapp

docker build -t h2flaskapp .

7. Now we will push this image to dockerhub reppo

- first we will tage our image for which we will login docker

docker login --username=sakshamhere

- now we will tag

docker tag h2flaskapp sakshamhere/my_dockler_repo:latest

- now pushig to repo on dockerhub

docker image push sakshamhere/my_dockler_repo:latest