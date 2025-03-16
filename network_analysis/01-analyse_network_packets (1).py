# STEP-1 Download the npcap installer from the official website: npcap Downloads (https://npcap.com/#download)
# STEP-2 RESTART PC

"""
Packet Sniffing, capturer et analyser les paquets à partir d’une interface réseau.
Il fournit des informations sur la communication entre les appareils, les protocoles utilisés,
et le type de données échangées. Le reniflage de paquets est une technique fondamentale en réseau
analyse et peut être utile à diverses fins, notamment le dépannage, la surveillance de la sécurité,
et l'optimisation du réseau.
"""
from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

sniff(count=10, prn=packet_callback)
