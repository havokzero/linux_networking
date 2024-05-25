# Linux Networking

A comprehensive and user-friendly script for diagnosing and managing network issues on Linux systems. This script is designed to work in various environments, including physical machines and virtual machines (VMware, Oracle VM).

## Features

- **Detection and Display**: Automatically detects and displays the Linux distribution and whether the environment is a physical or virtual machine.
- **Network Interfaces**: Lists all network interfaces with detailed information about each.
- **Diagnosis**: Diagnoses common network issues such as interfaces being down or lacking an IPv4 address.
- **Issue Resolution**: Prompts the user to fix detected issues and attempts to resolve them.
- **Connectivity Check**: Checks internet connectivity and fetches the external IP address.
- **Main Menu**: Provides a main menu for easy navigation and selection of actions.
- **TryHackMe VPN Integration**: Checks the TryHackMe VPN connection status without requiring the VPN configuration file path.

## Requirements

- Python 3.x
- `colorama` library for colored output
- `sudo` privileges for certain network management tasks

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/havokzero/linux_networking.git
    cd linux_networking
    ```

2. Install the required Python package:
    ```bash
    pip install colorama
    ```

3. Make the script executable:
    ```bash
    chmod +x fix_network.py
    ```

## Usage

Run the script with the following command:
```bash
./fix_network.py
