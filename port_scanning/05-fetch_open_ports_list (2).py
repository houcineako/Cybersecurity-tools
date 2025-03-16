# Import the necessary module for network scanning
import nmap

def check_ports(target):
    # Create a PortScanner object
    nm = nmap.PortScanner()

    try:
        # Perform a TCP SYN scan to identify open ports
        nm.scan(hosts=target, arguments='-sS')
    except nmap.PortScannerError as e:
        # Handle potential errors during the scan
        print(f"Error: {e}")
        return

    # Lists to store open and closed ports
    open_ports = []
    closed_ports = []

    # Iterate through all discovered hosts
    for host in nm.all_hosts():
        print(f"Scan results for {host}:")
        # Iterate through ports and determine their state
        for port in nm[host]['tcp']:
            port_info = nm[host]['tcp'][port]
            if port_info['state'] == 'open':
                open_ports.append(port)
            elif port_info['state'] == 'closed':
                closed_ports.append(port)

    # Print the results
    print(f"\nOpen Ports: {open_ports}")
    print(f"Closed Ports: {closed_ports}")

if __name__ == "__main__":
    # Prompt the user to enter the target IP address or range
    target = input("Enter target IP address or range: ")
    # Call the check_ports function to perform the scan and display the results
    check_ports(target)