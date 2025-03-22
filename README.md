# dpp-configurator

# What is dpp-configurator?

dpp-configurator is a Wi-Fi configurator based on Wi-Fi Easy Connect and DPP (Device Provisioning Protocol). It typically works on a Linux Wi-Fi ready laptop PC.

dpp-configurator works as follows:
1. Configurator reads QR Code on enrollee devices. QR Code includes bootstrap information such as Wi-Fi channel, MAC address and public key of the device.
2. Using bootstrap information, configurator communicates with the enrollee device directly and informs it about SSID and password.
2. Enrollee device will connect to the Wi-Fi network using the SSID and password.

# Installation
1. Install dependenies

   dpp-configurator requires pcap and mbedtls.
   Example for Debian or Ubuntu case:
   ```bash
   sudo apt-get install libpcap-dev libmbedtls-dev
   ```

2. Clone code and make

   ```bash
   git clone https://github.com/nomlab/dpp-configurator.git
   cd dpp-configurator
   make
   ```

# How to use
1. Turn Wi-Fi Interface into Monitor Mode

   First, stop your system network managers (NetworkManager or something). Then, turn the Wi-Fi interface into monitor mode. For example:
   ```bash
   export DPP_IF=wap5e1 DPP_CH=6
   sudo systemctl stop NetworkManager
   sudo ifconfig $DPP_IF down
   sudo iwconfig $DPP_IF mode monitor
   sudo ifconfig $DPP_IF up
   sudo iwconfig $DPP_IF channel $DPP_CH
   ```
   `DPP_IF` can be found using `iwconfig`. `DPP_CH` depends on enrollee, but typically 6.

2. Run dpp-configurator

   Read QR Code with another tool, and get `PUBLIC_KEY`, `Enrollee_MAC_ADDR`. Then:
   ```bash
   sudo ./dpp-configurator <DPP_IF> <PUBLIC_KEY> <Enrollee_MAC_ADDR> <Configurator_MAC_ADDR>
   ```
   Actual command-line would look like:
   ```
   sudo ./dpp-configurator wap5e1 MDkwEw...fYswnE= 00:11:22:33:44:55: 66:77:88:99:AA:BB
   ```

3. Restore Wi-Fi Interface

   Turn the Wi-Fi back.
   ```bash
   export DPP_IF=wap5e1
   sudo ifconfig $DPP_IF down
   sudo iwconfig $DPP_IF mode managed
   sudo systemctl start NetworkManager
   ```
