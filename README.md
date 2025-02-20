# DPP-configurator

A collection of programs created to implement a configurator for Wi-Fi Easy Connect using DPP (Device Provisioning Protocol) . dpp-configurator advertises using bootstrap information of device joining the network. Bootstrap information includes the Wi-Fi channel to be used and the public bootstrap key. Originally, bootstrap information is published as a QR code or NEC tag, but in this implementation, decoded information contained in the QR Code is used.  

# Installation 
1. Clone code
   ```bash
   $ git clone --recursive git@github.com:nomlab/dpp-configurator.git
   ```

# Priparation
1. Edit `credential.json.sample`
   
   Set ssid and password for access point
   ```
   {"wi-fi_tech":"infra","discovery":{"ssid":"<SSID>"},"cred":{"akm":"psk","pass":"<PASSWORD>"}}
   ```
2. Rename file from `credential.json.sample` to `credential.json`
   ```bash
   $ mv credential.json.sample credential.json
   ```

# How to use
1. Setup NI ( Network Interface )
   ```bash
   $ sudo ./setup.sh <NI_NAME> <CHANNEL>
   ```
   NI_NAME can be found using command "iwconfig".
   CHANNEL is used to communicate with enrollee.

2. Compile dpp-configurator
   ```bash
   $ make
   ```

3. Run dpp-configurator

   1. main branch version
      ```bash
      $ sudo ./dpp-configurator <NI_NAME> 
      ```
   2. dev branch version
      ```bash
      $ sudo ./dpp-configurator <NI_NAME> <Public_Key (included in QR code)> <Enrollee_MAC_ADDR> <Configurator_MAC_ADDR>
      ```
   3. dev branch version (sample)
      ```
      $ sudo ./dpp-configurator wap5e1 MDkwEw ... fYswnE= 12:34:56:78:90:ab cd:ef:gh:ij:kl:mn  
      ```
4. Restore the Environment
   ```bash
   $ ./finish.sh <NI_NAME>
   ```
   






