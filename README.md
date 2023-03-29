# PySniffer (Wireless Network Tool)

This is a Python tool for capturing, analyzing, and cracking wireless network traffic using the Scapy library. The tool provides two main functions:

sniff_wireless(): Sniffs wireless network traffic and extracts the SSID, BSSID, and channel of each wireless network beacon frame.

crack_wep(): Cracks WEP encryption using an ARP injection attack and a specified WEP key.

This tool is intended for educational purposes only and should not be used for malicious activities. Always ensure that you have permission to perform security testing on a network before doing so.

## Usage:

1. Clone the repository to your local machine:
```python
git clone https://github.com/sainsec/PySniffer.git
```

2. Install the necessary dependencies:
```python 
pip install -r requirements.txt
```
3. Run the tool with the following command to sniff wireless network traffic:
```python
python pysniffer.py sniff INTERFACE
```
4. Run the tool with the following command to crack WEP encryption:
```python
python pysniffer.py crack INTERFACE BSSID CHANNEL SSID WEP_KEY
```
Replace INTERFACE, BSSID, CHANNEL, SSID, and WEP_KEY with the appropriate values for the network you want to target.
