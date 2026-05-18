# syntax=docker/dockerfile:1
FROM registry.suse.com/bci/bci-micro:latest
# we use a local image that is identical to the base image.
# we don't pull the base image directly in the ci unit test because we want to assert our action
# can manage local images.
COPY <<EOF /hello.txt
hello from image-pipeline action test
EOF
