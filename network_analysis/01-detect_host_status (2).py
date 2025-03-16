# STEP-1 Install nmap-7.94 in your pc
# STEP-2 Restart if required.

"""
Pour effectuer une simple analyse de découverte d'hôte à l'aide de l'outil Nmap. Nmap est un outil d'analyse de réseau open source populaire
qui peut être utilisé pour diverses tâches d’exploration du réseau et d’audit de sécurité.
"""

import nmap

class MyScanner:
    def __init__(self, target_ip_range):
        # Initialize the scanner with the target IP range
        self.target_ip_range = target_ip_range
        self.scan_result = None
        # Create an instance of the nmap.PortScanner class
        self.nm = nmap.PortScanner()

    def perform_scan(self):
        # Perform host discovery scan with the specified IP range and '-sn' option for ping scan
        self.scan_result = self.nm.scan(hosts=self.target_ip_range, arguments='-sn')

        # Check if the scan was successful
        if "scan" not in self.scan_result:
            print("Scan failed. Check your scan options and target IP range.")
            return

        # Print discovered hosts
        for host in self.nm.all_hosts():
            try:
                # Attempt to access detailed information for each discovered host
                detailed_info = self.scan_result["scan"][host]
                # Print the host's IP, state (up or down)
                print(f"Host: {host} is {detailed_info['status']['state']}")
            except KeyError:
                # Handle cases where detailed information is not available
                print(f"No detailed information available for {host}")

# Create an instance of the MyScanner class with the target IP range '192.168.1.1/24'
# Scans all addresses from 192.168.100.0 to 192.168.100.255
# /24 is the prefix length used to indicate the number of network bits of an IP addres

scanner = MyScanner('192.168.1.1/?')

# Perform the host discovery scan
scanner.perform_scan()
