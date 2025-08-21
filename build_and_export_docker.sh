#!/bin/bash
 
# Set variables
IMAGE_NAME="sandroid"
 
# Build the Docker image
echo "Building Docker image..."
docker build -t $IMAGE_NAME . -f docker/dockerfile
 
# Check if the build was successful
if [ $? -ne 0 ]; then
    echo "Docker image build failed. Exiting."
    exit 1
fi

echo "Saving and compressing compiled image to deploy/sandroid_image.tar.gz, this can take several minutes..."
#docker save -o deploy/sandroid_image.tar sandroid
docker save sandroid | gzip > deploy/sandroid_image.tar.gz
echo "Done."
 
# Run the Docker container
# echo "Running Docker container..."
# docker run --rm -it $IMAGE_NAME

# Run without building like so:
# sudo docker run -it --name sandroid --rm sandroid
