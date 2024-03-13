FROM node:13-alpine

ENV MONGO_DB_USERNAME = admin \
    MONGO_DB_PWD = password \       

# ITS BETTEER TO SPECIFY ENV VARIABLE IN COMPOSE FILE HOWERVER THIS IS AN ALTERNATIVE

RUN mkdir -p /home/app

# the run command runs inside container

COPY . /home/app

# the copy command runs on host/laptop as it copies from laptop 

CMD ["node","server.js"]

# cmd is an entrypoint , after this run commands runs