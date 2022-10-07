#!/bin/bash

# set env variables
export IMAGE_NAME=srp/arp
export VICTIM_NAME_1=station-1
export VICTIM_NAME_2=station-2
export ATTACKER_NAME=evil-station
export NETWORK_NAME=srp-lab

# stop all running containers
RUNNING_CONTAINERS=$(docker ps -q)

if [ -z "$RUNNING_CONTAINERS" ]; then
    echo "No running containers to stop."
else
    echo "Stoping running containers:"
    docker stop $RUNNING_CONTAINERS  
fi

# clean up
echo "Removing existing containers, networks, images ..."
docker container rm $VICTIM_NAME_1 $VICTIM_NAME_2 $ATTACKER_NAME
docker network rm $NETWORK_NAME
docker image rm $IMAGE_NAME

# build a new image
echo "Building a new image $IMAGE_NAME ..."
docker-compose build

# create and start containers in detached mode
echo "Creating and starting containers ..."
docker-compose up -d