
# in this senerio we are making mongo and mongo-express containers work in same network and connect them with JS application

# create docker network
docker network create mongo-network

# start mongodb
docker run -d \
-p 27107:27107 \
-e MONGO_INITDB_USERNAME= admin \
-e MONGO_INITDB_ROOT_PASSWORD = password \
--net mongo-network \
--name mongodb \
mongo

# start mongo-express
docker run -d \
-p 8080:8081 \
-e ME_CONFIG_MONGODB_ADMINUSERNAME = admin \
-e ME_CONFIG_MONGODB_ADMINPASSWORD = password \
-e ME_CONFIG_MONGODB_SERVER  = mongodb \
--net mongo-network \
--name mongo-express \
mongo-express