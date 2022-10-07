# Create ubuntu as base image
FROM ubuntu

# Install packages
RUN DEBIAN_FRONTEND=noninteractive \
    TZ=Europe \
    apt-get update && apt-get install -y \
    iputils-ping \
    nmap \
    net-tools \
    dsniff \
    tcpdump \
    netcat \
    && rm -rf /var/lib/apt/lists/*
