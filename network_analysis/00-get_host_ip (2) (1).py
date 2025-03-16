# Récupérer l'adresse IP de l'hôte
"""
Si vous possédez un ou deux appareils à la maison avec une adresse IP dite 192, ou une adresse IP privée commençant par 192.168.
Il s'agit du format d'adresse IP privée par défaut le plus couramment attribué aux routeurs réseau du monde entier.
"""

import socket

hostname = input("Please enter website address:\n")

# IP lookup from hostname
try:
    print(f'The {hostname} IP Address is {socket.gethostbyname(hostname)}')

except socket.gaierror as e:
    print(f'Invalid hostname, error raised is {e}')


# scanme.nmap.org
# 45.33.32.156
# example.org
# google 8.8.8.8
# localhost 127.0.0.1



