"""
Analyse des ports réseau à l'aide d'une technique d'analyse TCP SYN. Le but de ce script est de découvrir les ports ouverts sur une machine cible.
Le code utilise la bibliothèque Scapy pour créer et envoyer des paquets TCP SYN aux ports spécifiés sur la cible.
Adresse IP, puis analyse les réponses pour déterminer si les ports sont ouverts.
"""

from scapy.all import IP, TCP, sr

# Perform a TCP SYN scan on a target IP for common ports

target_ip = "192.168.1.254" # First try with your IP address
# target_ip = "103.102.166.224" #  Later try wikipedia
ports = [22, 80, 443, 8080]

# Create SYN packets
packets = IP(dst=target_ip) / TCP(dport=ports, flags="S")

# Send packets and receive responses
responses, _ = sr(packets, verbose=1, timeout=1)

# Display open ports
for packet in responses:
    if packets[1][TCP].flags == "SA":
        print(f"Port {packet[1][TCP].sport} is open.")
