# DPP-configurator

A collection of programs created to implement a configurator for Wi-Fi Easy Connect using DPP (Device Provisioning Protocol) . DPP-configurator advertises using bootstrap information of device joining the network. Bootstrap information includes the Wi-Fi channel to be used and the public bootstrap key. Originally, bootstrap information is published as a QR code or NEC tag, but in this implementation, decoded information contained in the QR Code is used. 

# Installation 
1. Clone code
   ```bash
   $ git clone --recursive 
   ```

# How to use
1. Setup NI ( Network Interface )
   ```bash
   $ sudo ./setup.sh <NI_NAME> <CHANNEL>
   ```
   NI_NAME can be found using command "iwconfig".
   CHANNEL is used to communicate with enrollee.

2. Compile DPP-configurator
   ```bash
   $ make
   ```

3. Run DPP-configurator
   ```bash
   $ sudo ./dpp-configurator <NI_NAME>
   ```






