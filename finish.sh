#!/bin/bash

# Check if the NI (Network Interface) name and channel are provided as Args

if [ -z "$1" ]; then
  echo "Usage: $0 <network_interface>"
  exit 1
fi

# Get Attributes from Args
INTERFACE=$1

# Disable the NI 
sudo ifconfig $INTERFACE down

# Set the NI to managed mode
sudo iwconfig $INTERFACE mode managed

# Start the NetworkManager service
sudo systemctl start NetworkManager






