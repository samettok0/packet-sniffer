# Packet Sniffer

A simple packet sniffer written in C using the libpcap library. This tool captures network packets from a specified network interface.

## Overview

This project demonstrates the basics of packet capture in C. In this first part, the sniffer:
- Opens a network interface in promiscuous mode
- Captures a specified number of packets (currently set to 5)
- Outputs a simple message for each captured packet

## Prerequisites

- C compiler (gcc/clang)
- libpcap development package

### Installation on macOS

```bash
# Install libpcap using Homebrew
brew install libpcap
```

### Installation on Linux

```bash
# Debian/Ubuntu
sudo apt-get install libpcap-dev

# Fedora/RHEL
sudo dnf install libpcap-devel
```

## Building the Project

```bash
# Compile the packet sniffer
gcc -o packetsniff packetsniff.c -lpcap
```

## Usage

```bash
# May need root permissions to capture packets
sudo ./packetsniff
```

> **Note:** The current implementation uses "en0" as the network interface. You may need to change this to match your system's network interface name.

## Configuration

To modify the network interface or number of packets to capture, edit the following variables in `packetsniff.c`:

- `char *device = "en0";` - Set to your network interface name
- `int packet_count = 5;` - Change to capture more or fewer packets

## Features (Part 1)

- Basic packet capture capability
- Simple callback function for packet processing
- Error handling for pcap operations


