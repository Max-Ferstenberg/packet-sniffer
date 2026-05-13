# C++ CLI Packet Sniffer

A network packet capture and analysis tool written in C++ with libpcap.Designed as a learning project to understand low-level packet parsing and as a companion to my [DNS Tunnel Detector](https://github.com/yourusername/dns-tunnel-detector).

> **This is actively a WIP; this README will be expanded upon, current code is functional but is being extended**

## What it does

- Lists network interfaces
- Captures traffic with libcap using [BPF filter expressions](https://www.tcpdump.org/manpages/pcap-filter.7.html)
- Parses Ethernet (incl. VLAN 802.1Q/802.1ad frames)
- Parses IPv4 with proper header validation
- Parses TCP with flag decoding
- Parses UDP with port and length info
- Parses ICMP with type/code/checksum
- Parses ARP
- Displays payloads (where they're readable)

## Roadmap

In progress/planned:
- DNS message parsing
- PCAP file output
- IPv6 parsing
- Hex/ASCII payload dump
- Protocol statistics
- Portable build
- Complete ARP output formatting

- ## Build


```bash
g++ -std=c++17 -Wall -Wextra -o packetsniffer main.cpp -lpcap
```

I'll get it working with CMake soon, don't worry :)

## Run

Requires root or CAP_NET_RAW


```bash
sudo ./packetsniffer
```

Then, just navigate the CLI!
The tool will prompt for:
1. Network interface (chosen from a numbered list)
2. BPF filter expression (optional; e.g. `tcp port 80`, `udp and host 8.8.8.8`)
3. Netmask (optional)
4. Number of packets to capture

## Dependencies

- C++17 or newer
- libcap (`apt install libpcap-dev` if you need)

## Author
Max Ferstenberg
