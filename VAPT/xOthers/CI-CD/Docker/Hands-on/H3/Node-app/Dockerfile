# Since this is a node application
FROM node:14 

# setting my workdir
WORKDIR /app

# Copying the requirements.tx, in case of node the dependency file is package.jsom
# instead of again mentionning /app we could have also writeen like COPY pakage.json .
COPY package.json /app

# running the requirements file to install all dependencies
RUN npm install

# now we will copy all the app files in our image
COPY . .

# now since the application listens on port 80 so we will expose it (check last line of server.js)
EXPOSE 80

# We add Volume here (do this after understanding problem without volume following Notes.md)
# this is anonymous volumes which gets removed when container is removed hence of no use to our problem of persistence
#VOLUME [ "/app/feedback" ]

#now the entrypoint (we could also have directly write CMD ["node","server.js"])
ENTRYPOINT [ "node" ]

# the intial command
CMD ["server.js"]