A fast and efficient port scanning tool written in C that allows for both targeted port scanning and subnet discovery. This tool leverages multi-threading to perform scans quickly, making it suitable for network reconnaissance and security auditing.

## Features

- **Domain-to-IP Resolution**: Convert domain names to IP addresses for scanning
- **Custom Port Scanning**: Specify individual ports to scan
- **Default Port Scanning**: Quick scan of common service ports
- **Subnet Scanning**: Discover active hosts in a local subnet and scan their ports
- **Multi-threading**: Parallel scanning for improved performance
- **Configurable**: Customize thread count and scan targets

## Requirements

- GCC compiler
- POSIX-compliant operating system (Linux, macOS, etc.)
- pthread library

## Installation

Clone the repository and compile using the provided makefile:

```bash
git clone https://github.com/yourusername/port-scanner.git
cd port-scanner
make
```

## Usage

Run the compiled binary:

```bash
./port-scanner
```

### Options

When running the tool, you'll be presented with two main options:

1. **Domain Port Scan**: Scan specific ports on a target domain/IP
    
    - Enter the domain name or IP address
    - Choose specific ports to scan
    - Set the number of parallel threads
2. **Default Local Subnet Scan**: Automatically scan your local subnet
    
    - Discovers active hosts on the network
    - Scans common ports on all discovered hosts
    - Uses optimized multi-threading for fast discovery

## How It Works

The scanner uses the following techniques:

- **Socket Programming**: Creates TCP connections to detect open ports
- **Multi-threading**: Distributes scanning workload across multiple threads
- **Connection Timeouts**: Properly configured timeouts to balance speed and accuracy
- **DNS Resolution**: Resolves domain names to IP addresses using getaddrinfo()

## Customizing Subnet Settings

For subnet scanning, the tool is configured for typical network layouts. If your subnet is different (e.g., 10.0.0.x or 172.16.x.x), you may need to modify the `blockOne`, `blockTwo`, and `blockThree` variables in the `defaultScan()` function to match your network.

## Architecture

The codebase is structured as follows:

- **main.c**: Contains the main program flow and user interface
- **scanner.c**: Implements port scanning and host discovery functionality
- **input_parser.c**: Handles domain resolution and user input processing
- **head.h**: Contains all necessary header files and global definitions

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Security Notice

This tool is intended for legitimate network administration and security testing. Only use it on networks you own or have explicit permission to scan. Unauthorized port scanning may be illegal in many jurisdictions.

## License

This project is licensed under the MIT License - see the LICENSE file for details.