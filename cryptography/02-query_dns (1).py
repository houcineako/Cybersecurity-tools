"""
Pour effectuer une requête DNS (Domain Name System) à l'aide de la bibliothèque Scapy en Python.
Le but du code est d'envoyer une requête DNS à un serveur DNS spécifié (dans ce cas, le serveur DNS public de Google à l'adresse "8.8.8.8").
Pour un nom de domaine particulier (« wikipedia.com »). Il imprime ensuite les détails de la réponse DNS.
"""

from scapy.all import IP, UDP, DNS, DNSQR, sr1

def dns_query(target_domain):
    packet = IP(dst="8.8.8.8") / UDP() / DNS(rd=1, qd=DNSQR(qname=target_domain))
    response = sr1(packet, verbose=0)
    if response:
        response.show()


dns_query("wikipedia.com")
