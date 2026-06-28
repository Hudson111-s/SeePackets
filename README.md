> [!WARNING]  
> This project is still in development and may be unstable.


# SeePackets
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)


A lightweight packet sniffer written in C using raw sockets.


## Current features

- IPv4 / IPv6 support
- TCP, UDP, ICMP, and ARP parsing
- Protocol filtering
- Port filtering for TCP/UDP
- Output files


## Platform Support

**SeePackets** is currently restricted to Linux systems because it relies exclusively on `AF_PACKET` found in the Linux kernel. 
Support for other systems may be added in the future.


## Build instructions

**SeePackets** uses CMake to build, please follow the following steps to build:

### Requirements

- C compiler (GCC, Clang)
- CMake 3.15+

### Build steps

1. **Clone the repository**

    ```bash
    git clone https://github.com/Hudson111-s/SeePackets.git
    cd SeePackets
    ```


2. **Build**

    ```bash
    cmake -S . -B build
    cmake --build build
    ```


## Usage

```bash
Usage: ./SeePackets [options]
Options:
  -i, --iface <iface>      Network interface (default: eth0)
  -4, --ip <addr>          IPv4 address filter
  -6, --ip6 <addr>         IPv6 address filter
  -p, --port <port>        Port filter (for udp and tcp only)
  -P, --proto <proto>      Protocol (tcp,udp,icmp,arp)
  -f, --file <path>        Output file
  --ipv4-only              Only filter for ipv4
  --ipv6-only              Only filter for ipv6
  -h, --help               Display usage
```


## Contribution

Contributions are very welcome! Feel free to open [issues](https://github.com/Hudson111-s/SeePackets/issues) or submit [pull requests](https://github.com/Hudson111-s/SeePackets/pulls).


## Author

Created with ❤️ by [Hudson111-s](https://github.com/Hudson111-s)
