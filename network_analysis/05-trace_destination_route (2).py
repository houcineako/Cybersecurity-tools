"""
Traceroute est un outil de diagnostic réseau utilisé pour découvrir l'itinéraire emprunté par les paquets pour atteindre une adresse IP de destination.
Il fonctionne en envoyant une série de paquets avec des valeurs de durée de vie (TTL) croissantes et en observant les réponses des routeurs intermédiaires.
"""

from scapy.all import IP, UDP, ICMP, sr

def traceroute(target_ip, max_ttl=30):
    for ttl in range(1, max_ttl + 1):
        packet = IP(dst=target_ip, ttl=ttl) / UDP(dport=33434)
        response, _ = sr(packet, timeout=2, verbose=0)
        if response:
            print(f"{ttl}: {response[0][1].src}")
            if response[0][1].src == target_ip:
                break

# Example usage
traceroute("8.8.8.8")
