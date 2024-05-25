import os
import subprocess
import sys
import time
import getpass
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Define Colors for Output
def colour(col, text, delay=0):
    colours = {
        "green": Fore.GREEN,
        "red": Fore.RED,
        "yellow": Fore.YELLOW,
        "header": Fore.CYAN + Style.BRIGHT,
        "code": Fore.WHITE + Style.DIM,
        "process": Fore.BLUE
    }
    if col in colours:
        print(f"{colours[col]}{text}{Style.RESET_ALL}")
    if delay > 0:
        time.sleep(delay)

def run_command(command):
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True, text=True)
        return output.strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.strip()}"

def check_interfaces():
    return run_command("ip addr").splitlines()

def bring_interface_up(interface):
    colour("process", f"[+] Bringing up interface {interface}...")
    result = run_command(f"sudo ip link set {interface} up")
    if "Error" in result:
        colour("red", f"[-] Failed to bring up {interface}: {result}")
    else:
        colour("green", f"[+] Interface {interface} is now up.")

def restart_network_service(distro):
    colour("process", "[+] Restarting network service...")
    if "ubuntu" in distro or "debian" in distro:
        result = run_command("sudo systemctl restart NetworkManager")
    elif "arch" in distro or "manjaro" in distro:
        result = run_command("sudo systemctl restart NetworkManager")
    elif "fedora" in distro or "centos" in distro or "redhat" in distro:
        result = run_command("sudo systemctl restart NetworkManager")
    else:
        result = "Error: Unsupported Linux distribution"
    
    if "Error" in result:
        colour("red", f"[-] Failed to restart network service: {result}")
    else:
        colour("green", "[+] Network service restarted.")

def fetch_external_ip():
    colour("process", "[+] Fetching external IP address...")
    external_ip = run_command("curl -s ifconfig.me")
    if "Error" in external_ip:
        colour("red", f"[-] Failed to fetch external IP address: {external_ip}")
        return None
    else:
        colour("green", f"[+] External IP address: {external_ip}")
        return external_ip

def print_interface_info(interface, ip_info):
    colour("header", f"[+] {interface} Information:")
    for line in ip_info:
        if interface in line:
            print(f"{Fore.CYAN}{Style.BRIGHT}{line}")

def get_linux_distro():
    distro = run_command("lsb_release -is").lower()
    colour("header", f"[+] You are running: {distro.capitalize()}")
    return distro

def detect_vm():
    dmi_output = run_command("sudo dmidecode -s system-manufacturer").lower()
    if "vmware" in dmi_output:
        return "VMware"
    elif "oracle" in dmi_output:
        return "Oracle VM"
    else:
        return "Physical Machine"

def diagnose_and_fix_network(distro):
    interfaces = check_interfaces()
    problematic_interfaces = {}

    interface_names = ['eth0', 'wlan0', 'vboxnet0', 'pan0', 'vmnet1', 'vmnet8', 'ppp0', 'tun0']

    for name in interface_names:
        problematic_interfaces[name] = {
            'down': False,
            'no_ipv4': True,
            'info': []
        }

    for line in interfaces:
        for name in interface_names:
            if name in line:
                problematic_interfaces[name]['info'].append(line)
                if "state DOWN" in line:
                    problematic_interfaces[name]['down'] = True
                if "inet " in line:
                    problematic_interfaces[name]['no_ipv4'] = False

    changes_needed = False

    for name, status in problematic_interfaces.items():
        if status['down'] or status['no_ipv4']:
            changes_needed = True

    if changes_needed:
        colour("header", "[+] Network Diagnostics")
        for name, status in problematic_interfaces.items():
            if status['down']:
                colour("yellow", f"[!] {name} is down.")
            if status['no_ipv4']:
                colour("yellow", f"[!] {name} does not have an IPv4 address.")
        
        proceed = input("Do you want to attempt to fix these issues? (y/n): ").strip().lower()
        if proceed == 'y':
            if os.geteuid() != 0:
                colour("red", "[-] Script is being run as a low-privileged user", 1)
                colour("yellow", "Please enter your sudo password: ")
                password = getpass.getpass()
                os.execvp("sudo", ["sudo", "python3"] + sys.argv)
            else:
                for name, status in problematic_interfaces.items():
                    if status['down']:
                        colour("process", f"Attempting to bring up {name}...")
                        bring_interface_up(name)
                        interfaces = check_interfaces()  # Re-check interfaces
                        status['down'] = any(name in line and "state DOWN" in line for line in interfaces)
                        if status['down']:
                            colour("red", f"[-] Failed to bring {name} up. Restarting network service.")
                            restart_network_service(distro)
                        else:
                            colour("green", f"[+] {name} is now up after bringing it up manually.")
                            status['info'] = [line for line in check_interfaces() if name in line]

                    if status['no_ipv4']:
                        colour("process", f"Attempting to obtain IPv4 address for {name} via DHCP...")
                        result = run_command(f"sudo dhclient {name}")
                        if "Error" in result:
                            colour("red", f"[-] Failed to obtain IPv4 address for {name}: {result}")
                        else:
                            colour("green", f"[+] Successfully obtained IPv4 address for {name} via DHCP.")
                        status['info'] = [line for line in check_interfaces() if name in line]
        else:
            colour("yellow", "No changes were made.")
    else:
        colour("green", "[+] No issues detected with network interfaces.")

    # Display network interface information
    for name, status in problematic_interfaces.items():
        print_interface_info(name, status['info'])

    # Verify if eth0 has an IPv4 address after dhclient
    if problematic_interfaces['eth0']['no_ipv4']:
        colour("red", "[-] eth0 still does not have an IPv4 address. Further investigation needed.")
        return

    # Verify Internet Connection
    colour("process", "[+] Checking Internet connection by pinging 8.8.8.8...")
    internet_status = run_command("ping -c 1 -q 8.8.8.8")
    if "1 received" in internet_status:
        colour("green", "[+] Internet connection is working.")
    else:
        colour("red", "[-] Internet connection is not working. Restarting network service.")
        restart_network_service(distro)
        internet_status = run_command("ping -c 1 -q 8.8.8.8")
        if "1 received" in internet_status:
            colour("green", "[+] Internet connection restored after restarting network service.")
        else:
            colour("red", "[-] Failed to restore Internet connection. Further investigation needed.")
            return

    # Fetch and display external IP
    fetch_external_ip()

def list_relevant_network_info():
    colour("header", "[+] Listing all network interfaces:")
    nmcli_devices = run_command("nmcli device status")
    colour("code", nmcli_devices)
    
    ip_addr = run_command("ip addr")
    colour("code", ip_addr)
    
    ip_r = run_command("ip r")
    colour("code", ip_r)
    
    arp_cache = run_command("arp -a")
    colour("code", arp_cache)
    
    pci_devices = run_command("sudo lspci | grep -Ei 'eth|network|ethernet|wireless|wifi'")
    colour("code", pci_devices)

def check_tryhackme_connection(ovpn):
    ovpnoutput = run_command(f"openvpn {ovpn}")
    if "Initialization Sequence Completed" in ovpnoutput:
        colour("green", "[+] Connection Process completed successfully!")
    elif "Cannot load inline certificate file" in ovpnoutput or "certificate verify failed" in ovpnoutput:
        colour("red", "[-] Fatal Error: Inline Certificate is invalid")
        print("Please regenerate your VPN config on the access page (https://tryhackme.com/access)")
    elif "cipher AES-256-CBC" in ovpnoutput:
        colour("red", "[-] Using outdated switch for cipher negotiations. Attempting to update...")
        with open(ovpn, 'r') as file:
            filedata = file.read()
        filedata = filedata.replace('cipher AES-256-CBC', 'data-ciphers AES-256-CBC')
        with open(ovpn, 'w') as file:
            file.write(filedata)
        colour("green", "[+] Successfully updated cipher switch! Please connect to the VPN using the following command:")
        colour("code", f"sudo openvpn {ovpn}")
    else:
        colour("red", "[-] Failed to connect to TryHackMe VPN.")

def main_menu():
    try:
        while True:
            colour("header", "\nNetwork Diagnostics and Management")
            print(f"{Fore.YELLOW}1. List network interfaces")
            print(f"{Fore.YELLOW}2. Diagnose and fix network issues")
            print(f"{Fore.YELLOW}3. Fetch external IP address")
            print(f"{Fore.YELLOW}4. Check TryHackMe VPN connection")
            print(f"{Fore.YELLOW}5. Exit{Style.RESET_ALL}")
            choice = input("Enter your choice: ").strip()

            if choice == '1':
                list_relevant_network_info()
            elif choice == '2':
                diagnose_and_fix_network(distro)
            elif choice == '3':
                fetch_external_ip()
            elif choice == '4':
                ovpn = input("Enter the path to your TryHackMe VPN config file: ").strip()
                check_tryhackme_connection(ovpn)
            elif choice == '5':
                colour("green", "Exiting...")
                break
            else:
                colour("red", "Invalid choice. Please try again.")
    except KeyboardInterrupt:
        colour("red", "\nProcess interrupted by user. Exiting...")

if __name__ == "__main__":
    distro = get_linux_distro()
    vm_env = detect_vm()
    colour("header", f"[+] Environment: {vm_env}")
    main_menu()