
"""
Détection de version du service (-sV) et exécution de scripts NSE (Nmap Scripting Engine) par défaut (--script=default).
Le but du code est d'analyser une cible spécifiée (donnée sous forme d'adresse IP ou de plage) et de fournir des informations détaillées,
des informations sur les versions de service exécutées sur les ports ouverts de la cible.
"""

import nmap

class NmapScanner:
    def __init__(self, target):
        # Initialize the scanner with the target IP address or range
        self.target = target
        # Create an instance of the nmap.PortScanner class
        self.nm = nmap.PortScanner()

    def advanced_scan(self):
        # Perform an advanced scan with service version detection (-sV) and executing default NSE scripts (--script=default)
        self.nm.scan(hosts=self.target, arguments='-? --script=default')

        # Iterate through all discovered hosts
        for host in self.nm.all_hosts():
            # Print detailed results for each host
            print(f"Detailed results for {host}:")
            
            # Print service versions for open (Transmission Control Protocol) ports
            print(f"Service versions: {self.nm[host]['tcp'].items()}")


# Create an instance of the NmapScanner class with the target IP address '192.168.1.1'
scanner = NmapScanner('192.168.1.254')
#scanner = NmapScanner('45.33.32.156')

# Perform the advanced scan
scanner.advanced_scan()
