# Linux Networking

A comprehensive and user-friendly script for diagnosing and managing network issues on Linux systems. This script is designed to work in various environments, including physical machines and virtual machines (VMware, Oracle VM).

## Features

- Detects and displays the Linux distribution and environment (physical or virtual machine).
- Lists all network interfaces and provides detailed information.
- Diagnoses common network issues such as interfaces being down or lacking an IPv4 address.
- Prompts the user to fix detected issues and attempts to resolve them.
- Checks internet connectivity and fetches the external IP address.
- Includes a main menu for easy navigation and selection of actions.
- Integrates with TryHackMe VPN to check the VPN connection status.

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
