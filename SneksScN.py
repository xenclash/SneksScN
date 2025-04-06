#!/usr/bin/env python3

import nmap
import ipaddress
import argparse
from concurrent.futures import ThreadPoolExecutor
import distro

def validate_network(network):
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False

def get_active_ips(network):
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

    distro_name = distro.name(pretty=True)
    if not distro_name:
        return "Unknown Linux Distribution"
    return distro_name

def scan_network_and_identify_os(network):
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
    parser.add_argument("network", help="The network range or IP address to scan (e.g., 192.168.1.0/24 or 192.168.1.1).")
    args = parser.parse_args()

    network = args.network.strip()

    if not validate_network(network):
        print("Invalid network range or IP address. Please provide a valid CIDR notation (e.g., 192.168.1.0/24) or IP address.")
    else:
        scan_network_and_identify_os(network)