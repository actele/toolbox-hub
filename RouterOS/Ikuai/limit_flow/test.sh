#!/bin/zsh

# Create a container from the image
container_id=$(docker create actele/ikuai_helper)

# Copy the built binary from the container to the host
docker cp $container_id:/root/main ./test
docker cp $container_id:/root/config.yaml ./test
docker cp $container_id:/root/license ./test

# Clean up the container
docker rm $container_id

echo "The binary has been saved to ./test"


# 开启交互模式，方便进入容器测试
docker run -p 8088:8088 -it --entrypoint sh actele/ikuai_helper