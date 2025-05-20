# Packet Sniffer

A simple network packet sniffer written in C that captures and analyzes network traffic. The program can capture and display information about IPv4 packets, including TCP, UDP, and ICMP protocols.

## Features

- Captures IPv4 packets
- Supports multiple protocols:
  - TCP (with flag detection)
  - UDP
  - ICMP
- Displays detailed packet information:
  - Source and destination IP addresses
  - Protocol type
  - Port numbers (for TCP/UDP)
  - TCP flags (SYN, ACK, URG)
  - ICMP type and code
  - TTL and TOS values
  - Packet ID

## Requirements

- Linux/Unix-like operating system
- libpcap development library
- GCC compiler

### Installing Dependencies

On Ubuntu/Debian:
```bash
sudo apt-get install libpcap-dev
```

On macOS:
```bash
brew install libpcap
```

## Building

You can compile the program using either `cc` or `gcc`. Both commands will work:

Using `cc`:
```bash
cc -o packetsniff packetsniff.c -lpcap
```

Using `gcc`:
```bash
gcc -o packetsniff packetsniff.c -lpcap
```

> **Note:** `cc` is the traditional name for the C compiler on Unix systems. It's often a symbolic link to the actual compiler (like `gcc` or `clang`) on your system. Both commands will work the same way.

After compilation, run the program with sudo privileges:
```bash
sudo ./packetsniff <interface> <packet_count>
```

## Usage

```bash
./packetsniff <interface> <packet_count>
```

### Arguments

- `interface`: Network interface to capture packets from (e.g., en0, eth0)
- `packet_count`: Number of packets to capture (-1 for infinite capture)

### Examples

Capture 10 packets on interface en0:
```bash
./packetsniff en0 10
```

Capture packets indefinitely on interface en0:
```bash
./packetsniff en0 -1
```

## Output Format

The program displays packet information in the following format:

```
************************************
ID: <packet_id> | SRC: <source_ip> | DST: <dest_ip> | TOS: <tos> | TTL: <ttl>
PROTO: <protocol> | [Additional protocol-specific information]
```

### Protocol-specific Information

- TCP: Shows flags (S/A/U) and port numbers
- UDP: Shows source and destination ports
- ICMP: Shows type and code

## Notes

- The program requires root/administrator privileges to capture packets
- Use Ctrl+C to stop packet capture when running in infinite mode
- The program currently only supports IPv4 packets

## License

This project is open source and available under the MIT License.


