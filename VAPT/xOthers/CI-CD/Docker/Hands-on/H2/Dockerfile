# we are using ubuntu as base image, but ill use alpine as it is best practise to use smaller image
#FROM ubuntu          
FROM alpine

# now ill install python and also update the package manager ie apt
#RUN apt-get update -y && apt-get install -y python-pip python-dev
RUN apk add --update --no-cache python3 && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools 



# I will create aworking dir in image
WORKDIR /app

# I will now move app.py and requirements.txt to image, we can do this by ADD or COPY
ADD . /app

# now ill run the requirements.txt
RUN  pip install -r requirements.txt

# Now ill put my entrypoint 
ENTRYPOINT [ "python" ]

# we have to run app.y at start
CMD ["app.py"]