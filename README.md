🧪 Packet Sniffer
============================

A powerful network packet sniffer written in C that captures, analyzes, and displays network traffic with filtering capabilities. This tool enables network troubleshooting, protocol analysis, and monitoring of network communications.

---

✨ Features
----------

🧠 **Protocol Support**
- IPv4 packet analysis
- TCP with detailed flag information (SYN, ACK, FIN, RST, PSH, URG)
- UDP with length information
- ICMP with type and code descriptions

📡 **Display Information**
- Source and destination IP addresses with hostname resolution
- Service name identification for common ports
- Packet sizing in readable format (bytes/kilobytes)
- TCP flags, window sizes, and sequence numbers
- Accurate timestamps with microsecond precision
- Packet ID, TTL, and TOS values

🔍 **Filtering Capabilities**
- Supports Berkeley Packet Filter (BPF) syntax
- Filter by host, port, protocol, or combinations
- Advanced filtering options for specific packet types

⚙️ **Flexible Configuration**
- Command-line arguments for all settings
- Configurable packet count
- Selectable network interface
- Optional DNS resolution (with caching for performance)

---

📦 Requirements
------------
- Linux/Unix/macOS operating system
- libpcap development library
- C compiler (gcc or clang)
- Root/administrator privileges (required for packet capture)

---

🚀 Installation
------------

🛠 **Installing Dependencies**

**Ubuntu/Debian**
```bash
sudo apt-get install libpcap-dev gcc
```

**Fedora/RHEL/CentOS**
```bash
sudo dnf install libpcap-devel gcc
```

**macOS**
```bash
brew install libpcap
```

---

🔧 Building
--------

You can compile the program using either `cc` or `gcc`:

```bash
cc -o packetsniff packetsniff.c -lpcap
```

Or using:

```bash
gcc -o packetsniff packetsniff.c -lpcap
```

💡 `cc` is the traditional name for the C compiler on Unix systems. It's often a symbolic link to the actual compiler (like `gcc` or `clang`) on your system.

---

🧪 Usage
-----

```bash
sudo ./packetsniff <interface> <packet_count> [-n] [-f "filter"]
```

🔤 **Arguments**

| Argument | Description |
|----------|-------------|
| `<interface>` | Network interface to capture packets from (e.g., en0, eth0) |
| `<packet_count>` | Number of packets to capture (-1 for infinite capture) |
| `-n` | Disable DNS hostname resolution (optional) |
| `-f "filter"` | BPF filter expression to capture specific packets (optional) |

---

🧾 Examples
--------

**Basic packet capture:**
```bash
sudo ./packetsniff en0 10
```

**Capture packets indefinitely:**
```bash
sudo ./packetsniff en0 -1
```

**Capture only HTTPS traffic:**
```bash
sudo ./packetsniff en0 20 -f "port 443"
```

**Capture packets from a specific host:**
```bash
sudo ./packetsniff en0 -1 -f "host google.com"
```

**Capture only TCP packets with SYN flag (connection attempts):**
```bash
sudo ./packetsniff en0 10 -f "tcp[tcpflags] & tcp-syn != 0"
```

**Capture DNS traffic without hostname resolution:**
```bash
sudo ./packetsniff en0 30 -n -f "udp port 53"
```

---

🧠 BPF Filter Cheatsheet
----------------

| Expression | Matches |
|------------|---------|
| `host example.com` | Only packets to/from example.com |
| `port 80` | Only HTTP traffic |
| `tcp` | Only TCP packets |
| `udp` | Only UDP packets |
| `icmp` | Only ICMP packets |
| `src 192.168.1.1` | Only packets from a specific IP |
| `dst port 443` | Only packets to HTTPS ports |
| `udp port 53` | Only DNS traffic |
| `tcp[tcpflags] & tcp-syn != 0` | Only TCP SYN packets |
| `ether host 00:11:22:33:44:55` | Filter by MAC address |
| `ip broadcast` | Only broadcast packets |
| `ip multicast` | Only multicast packets |

🔗 **Combine filters:**
```bash
sudo ./packetsniff en0 -1 -f "host google.com and not port 443"
```

---

🖨 Output Format
------------

```
[HH:MM:SS.μμμμμμ] Packet XXX B
----------------------------------------
IP Header:
  ID: XXXXX | TTL: XX | TOS: 0xXX
  Source: XXX.XXX.XXX.XXX (hostname)
  Destination: XXX.XXX.XXX.XXX (hostname)
Transport Layer:
  Protocol: XXX
  Source Port: XXX (Service)
  Destination Port: XXX (Service)
  [Protocol-specific information]
----------------------------------------
```

**Protocol-specific Information**
- **TCP**: Shows flags, window size, sequence number
- **UDP**: Shows length
- **ICMP**: Shows type and code with descriptions

---

🛠 Troubleshooting
--------------

❗ **Permission Denied**  
If you see "Permission denied" errors, ensure you're running with sudo/root:
```bash
sudo ./packetsniff en0 10
```

❗ **Interface Not Found**  
Verify your network interface name with:
```bash
# On Linux
ip addr

# On macOS
ifconfig
```

❗ **Invalid Filter Syntax**  
If your filter fails to compile, check the syntax. Common issues include:
- Missing quotes around complex expressions
- Typos in protocol names
- Missing logical operators between clauses

---

🚫 Limitations
-----------
- ❌ Currently supports IPv4 only (no IPv6)
- ❌ Cannot decrypt encrypted traffic (e.g., HTTPS content)
- ❌ Minimal packet payload analysis

---

🌱 Future Improvements
------------------
- ✅ IPv6 support
- ✅ Traffic statistics generation
- ✅ Packet payload inspection
- ✅ Export to PCAP format
- ✅ Colorized output

---

📜 License
-------

This project is open source and available under the MIT License.

---

📚 References
----------
- 📘 [libpcap Documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html)
- 🔍 [Berkeley Packet Filter (BPF) Syntax](https://biot.com/capstats/bpf.html)
- 📖 [TCP/IP Illustrated](https://en.wikipedia.org/wiki/TCP/IP_Illustrated)


