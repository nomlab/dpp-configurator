#!/bin/bash

# Check if the NI (Network Interface) name and channel are provided as Args

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <network_interface> <channel>"
  exit 1
fi

# Get Attributes from Args
INTERFACE=$1
CHANNEL=$2

# Stop the NetworkManager service
sudo systemctl stop NetworkManager

# Disable the NI 
sudo ifconfig $INTERFACE down

# Set the NI to monitor mode
sudo iwconfig $INTERFACE mode monitor

# Able the  NI
sudo ifconfig $INTERFACE up

# Set the NI channel to 6
sudo iwconfig $INTERFACE channel $CHANNEL
