# stop all running containers
RUNNING_CONTAINERS=$(docker ps -q)

if [ -z "$RUNNING_CONTAINERS" ]; then
    echo "No running containers."
else
    echo "Stoping and removing running containers:"
    docker stop $RUNNING_CONTAINERS
    docker container rm $RUNNING_CONTAINERS
fi
