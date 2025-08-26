# Packet Sniffer – CodeAlpha Internship Project

## 📌 Overview
This project is a simple **Network Packet Sniffer** implemented in Python using the [Scapy](https://scapy.net/) library.  
It captures live packets on the network interface, extracts useful information (IP addresses, protocols, ports), and attempts to display the payload in a human-readable form.

This was developed as part of the **CodeAlpha Cybersecurity Internship**.

---

## 🚀 Features
- Captures live network packets using Scapy.
- Extracts:
    - Source & destination IP addresses
    - Protocol used (TCP / UDP / others)
    - TCP/UDP ports
    - Application data payload (first 300 characters by default).
- Gracefully handles undecodable payloads.

---

## 📋 Requirements
- Python 3.6+
- Scapy library
- Administrator/Root privileges (required for packet capture)

---

## 🔧 Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd Network-Packet-Sniffer
   ```

2. **Install required dependencies:**
   ```bash
   pip install scapy
   ```

3. **For Windows users:**
   - Install [Npcap](https://nmap.org/npcap/) or WinPcap for packet capture functionality
   - Run Command Prompt or PowerShell as Administrator

4. **For Linux/macOS users:**
   - Ensure you have root privileges or use `sudo`

---

## 🚀 Usage

**Run the packet sniffer:**
```bash
# Windows (as Administrator)
python Sniffer.py

# Linux/macOS (with sudo)
sudo python3 Sniffer.py
```

The program will start capturing packets and display information in the following format:
```
Packet sniffing...
Packet from 192.168.1.100 to 93.184.216.34 using protocol 6
  TCP ports: 54321 --> 80
  Payload: GET / HTTP/1.1
Host: example.com
...
```

**To stop the sniffer:** Press `Ctrl+C`

---

## ⚠️ Limitations

- **HTTPS/SSL Traffic**: Encrypted traffic (HTTPS, SSL/TLS) payloads cannot be decrypted and will appear as binary data. Only packet headers (IP addresses, ports) are visible.
- **Network Interface**: Captures packets only on the default network interface
- **Performance**: May impact system performance during high network traffic
- **Payload Decoding**: Some binary protocols may not decode properly to readable text
- **Promiscuous Mode**: Depends on network infrastructure; may only capture packets intended for the host machine
- **IPv6**: Currently focused on IPv4 traffic analysis

---

## 🔒 Legal Disclaimer

**⚠️ IMPORTANT**: This tool is for educational and authorized testing purposes only.

- Only use on networks you own or have explicit permission to monitor
- Unauthorized packet sniffing may violate laws and regulations
- Respect privacy and data protection laws
- The author is not responsible for any misuse of this software

---

## 🛠️ Technical Details

### File Structure
```
Network-Packet-Sniffer/
├── Sniffer.py    # Main packet sniffer script
└── README.md           # Project documentation
```

### How It Works
1. Uses Scapy's `sniff()` function to capture live packets
2. Filters for IP packets and extracts header information
3. Identifies transport layer protocols (TCP/UDP)
4. Attempts to decode application layer data as text
5. Handles decoding errors gracefully

---



## 🤝 Contributing

This project was created as part of the CodeAlpha internship. Feel free to fork and improve upon it!

For questions or suggestions, contact: **yousefelmenshawi@aucegypt.edu**
