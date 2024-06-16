#!/bin/sh

# Build the Docker image
docker build -t ikuai_helper .

# Create a container from the image
container_id=$(docker create ikuai_helper)

# Copy the built binary from the container to the host
docker cp $container_id:/root/main ./main

# Clean up the container
docker rm $container_id

echo "The binary has been saved to ./main"

# Save the Docker image to a tar file
docker save -o ikuai_helper.tar ikuai_helper

echo "Docker image has been saved to ikuai_helper.tar"