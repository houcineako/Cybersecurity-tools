"""
Pour fournir un script flexible et modulaire afin d'effectuer des analyses de réseau agressives avec Nmap,
en se concentrant spécifiquement sur les empreintes digitales du système d'exploitation et en enregistrant les résultats détaillés dans un format structuré (JSON).
Cela peut être utile aux professionnels de la sécurité, aux administrateurs de système ou à toute personne souhaitant comprendre
les caractéristiques et les vulnérabilités potentielles des appareils sur un réseau.
"""

import nmap
import json

nm = nmap.PortScanner()

def aggressive_scan(target):
    # Dictionary to store the scan results
    scan_results = {}
    try:
        # Perform an aggressive scan with OS fingerprinting
        nm.scan(hosts=target, arguments='-A -O')
    except nmap.PortScannerError as e:
        print(f"Error: {e}")
        return

    # Iterate through all discovered hosts
    for host in nm.all_hosts():
        # Collect relevant information about each host
        host_data = {
            'hostname': nm[host].hostname(),
            'state': nm[host].state(),
            'os_info': nm[host]['osmatch'][0]['name'] if 'osmatch' in nm[host] else 'Unknown',
            'tcp_ports': {port: nm[host]['tcp'][port] for port in nm[host]['tcp'].keys()},
            'udp_ports': {port: nm[host]['udp'][port] for port in nm[host]['udp'].keys()} if 'udp' in nm[host] else {}
        }
        # Store the host data in the scan_results dictionary
        scan_results[host] = host_data

    # Save the scan results to a JSON file
    json_file_path = f'03-scan_results_aggressive_{target.replace("/", "_")}.json'
    with open(json_file_path, 'w') as json_file:
        json.dump(scan_results, json_file, indent=2)
        print(f"Aggressive scan results saved to: {json_file_path}")

if __name__ == "__main__":
    # Execute scan      
    try:
        # Continuously prompt the user for target IP address or range until Ctrl+C is pressed
        while True:
            target = input("Enter target IP address or range (Ctrl+C to cancel): ")
            aggressive_scan(target)
    except KeyboardInterrupt:
        print("\nScan canceled. Exiting...")