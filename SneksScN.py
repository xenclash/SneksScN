#!/usr/bin/env python3

import nmap
import ipaddress
import argparse
from concurrent.futures import ThreadPoolExecutor
import distro

# Basic user interface header
print("""
 .oooooo..o                       oooo                  .oooooo..o           ooooo      ooo 
d8P'    `Y8                       `888                 d8P'    `Y8           `888b.     `8' 
Y88bo.      ooo. .oo.    .ooooo.   888  oooo   .oooo.o Y88bo.       .ooooo.   8 `88b.    8  
 `"Y8888o.  `888P"Y88b  d88' `88b  888 .8P'   d88(  "8  `"Y8888o.  d88' `"Y8  8   `88b.  8  
     `"Y88b  888   888  888ooo888  888888.    `"Y88b.       `"Y88b 888        8     `88b.8  
oo     .d8P  888   888  888    .o  888 `88b.  o.  )88b oo     .d8P 888   .o8  8       `888  
8""88888P'  o888o o888o `Y8bod8P' o888o o888o 8""888P' 8""88888P'  `Y8bod8P' o8o        `8 """)
print("                  Created by Marcelo M / @Xenclash on Github                        \n")

def validate_network(network):
    """Validate the provided network range or IP address."""
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False

def get_active_ips(network):
    """Scan the network for active devices."""
    nm = nmap.PortScanner()
    print(f"Currently scanning network: {network}...")
    try:
        nm.scan(hosts=network, arguments='-sn')
    except Exception as e:
        print(f"Error scanning network: {str(e)}")
        return []
    
    active_ips = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            active_ips.append(host)
    
    return active_ips

def get_os_info(ip):
    """Get the operating system information for a specific IP."""
    nm = nmap.PortScanner()
    try:
        print(f"Scanning OS information for {ip}...")
        nm.scan(ip, arguments='-O')
        
        if ip in nm.all_hosts() and 'osmatch' in nm[ip] and nm[ip]['osmatch']:
            os_info = nm[ip]['osmatch'][0].get('name', 'Unknown OS')
            return os_info
        else:
            return "OS info not detected"
    except Exception as e:
        return f"Error: {str(e)}"

def get_linux_distro():
    """Get the Linux distribution of the host machine."""
    try:
        distro_name = distro.name(pretty=True)
        if not distro_name:
            return "Unknown Linux Distribution"
        return distro_name
    except Exception as e:
        return f"Error detecting Linux distribution: {str(e)}"

def scan_network_and_identify_os(network):
    """Scan the network for active devices and identify their operating systems."""
    active_ips = get_active_ips(network)
    if not active_ips:
        print("No active devices found.")
        return

    print(f"Found {len(active_ips)} active devices.")

    devices = []
    with ThreadPoolExecutor() as executor:
        results = executor.map(get_os_info, active_ips)
        devices = list(zip(active_ips, results))

    if not devices:
        print("No devices found with OS information.")
        return

    print("\nScan Results:")
    print(f"{'IP Address':<15} {'Operating System'}")
    print("-" * 40)
    for device in devices:
        print(f"{device[0]:<15} {device[1]}")

    print(f"\nTotal devices found: {len(devices)}")

    linux_distro = get_linux_distro()
    print(f"\nHost Linux Distribution: {linux_distro}")

    return devices

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan a network or IP for active devices and OS information.")
    parser.add_argument(
        "network",
        nargs="?",
        default="192.168.1.0/24",
        help="The network range or IP address to scan (default: 192.168.1.0/24)."
    )
    args = parser.parse_args()

    network = args.network.strip()

    if not validate_network(network):
        print("Invalid network range or IP address. Please provide a valid CIDR notation (e.g., 192.168.1.0/24) or IP address.")
    else:
        scan_network_and_identify_os(network)