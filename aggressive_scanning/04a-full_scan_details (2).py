import nmap
import json

nm = nmap.PortScanner()

def perform_full_scan(target):
    try:
        # Perform a comprehensive scan including host discovery, port scanning, service version detection,
        # OS fingerprinting, and script scanning
        nm.scan(hosts=target, arguments='-sS -sV -O --script=default')
    except nmap.PortScannerError as e:
        # Handle potential errors during the scan
        print(f"Error: {e}")
        return

    # Collect scan results in a structured format
    scan_results = {}

    # Iterate through all discovered hosts
    for host in nm.all_hosts():
        # Collect relevant information about each host
        host_data = {
            'hostname': nm[host].hostname(),
            'state': nm[host].state(),
            'os_info': nm[host]['osmatch'][0]['name'] if 'osmatch' in nm[host] else 'Unknown',
            'tcp_ports': {port: nm[host]['tcp'][port] for port in nm[host]['tcp'].keys()} if 'tcp' in nm[host] else {},
            'udp_ports': {port: nm[host]['udp'][port] for port in nm[host]['udp'].keys()} if 'udp' in nm[host] else {},
            'scripts': {script_name: nm[host]['scripts'][script_name] for script_name in nm[host]['scripts'].keys()} if 'scripts' in nm[host] else {}
        }
        # Store the host data in the scan_results dictionary
        scan_results[host] = host_data

    # Save the scan results to a JSON file
    json_file_path = f'04-full_scan_results_{target.replace("/", "_")}.json'
    with open(json_file_path, 'w') as json_file:
        json.dump(scan_results, json_file, indent=2)
        print(f"Full scan results saved to: {json_file_path}")

if __name__ == "__main__":
    # Prompt the user to enter the target IP address or range
    target = input("Enter target IP address or range: ")

    # Perform the comprehensive scan   
    perform_full_scan(target)