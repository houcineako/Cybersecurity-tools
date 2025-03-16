"""
Enquête détaillée en capturant et en enregistrant les paquets réseau.
Utiliser la fonction sniff de Scapy pour capturer un nombre spécifié de paquets (dans ce cas, 100 paquets)
puis utilise la fonction wrpcap pour écrire ces paquets capturés dans un fichier PCAP (Packet Capture).
"""

from scapy.all import sniff, wrpcap

# sniff and capture packets to a file
packets = sniff(count=100)
wrpcap("captured_packets.pcap", packets)


# STEP-1 Download https://www.wireshark.org/download.html
# STEP-2 Install
# STEP-3 OPEN 'captured_packets.pcap' file and you can analyse each packet
