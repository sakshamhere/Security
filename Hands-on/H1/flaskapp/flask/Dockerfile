FROM python:3.7.2-stretch

RUN mkdir /app
# set a workdir in our container
WORKDIR /app

# copy all files in our container
ADD . /app

RUN pip install -r requirements.txt

#run the command to install uWSGI

CMD ["uwsgi","app.ini"]