# TCP Sniper

**Note:** This project is a cybersecurity major homework assignment that simulates TCP Reset Attack (TCP RST Attack) for educational purposes only. Use this tool only in controlled, educational environments.

## Project Overview

TCP Sniper demonstrates how TCP Reset attacks work by monitoring network traffic and automatically terminating unwanted TCP connections in real-time. It provides a graphical interface for managing IP blacklists and monitoring network traffic, helping students understand network security concepts and TCP protocol behavior.

![Screenshot](/images/screenshot.png)

## Features

- **Real-Time IP Blacklist Management**
  - Add or remove IP addresses from the blacklist while the program is running
  - No restart required for blacklist updates
  - Visual confirmation of blacklist changes

- **Network Traffic Monitoring**
  - Continuous scanning of local network traffic
  - Detection of TCP packets involving blacklisted IP addresses
  - Real-time packet display with detailed information

- **TCP Reset Attack Simulation**
  - Demonstrates how TCP RST attacks work
  - Immediate sending of TCP RST packets to both connection endpoints
  - Properly formatted RESET packets with accurate TCP fields (ports, sequence numbers, etc.)
  - Automatic termination of connections involving blacklisted IPs

- **User-Friendly GUI**
  - Built with CustomTkinter for a modern look and feel
  - Clear display of captured packets and terminated connections
  - Simple interface for blacklist management
  - Real-time connection statistics

## Prerequisites

- Python 3.x
- Scapy
- CustomTkinter

## Installation

1. Clone the repository:
```bash
git clone https://github.com/maybegal/tcp-sniper
cd tcp-sniper
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the program:
```bash
py main.py
```

2. Add IP addresses to the blacklist:
   - Enter an IP address in the input field
   - Click "Add" to include it in the blacklist
   - Click "Remove" to delete it from the blacklist

3. Start monitoring:
   - Click "Start Sniffing" to begin monitoring network traffic
   - The program will automatically detect and terminate connections involving blacklisted IPs
   - Click "Stop Sniffing" to pause the monitoring

## Project Structure

- `main.py`: Entry point of the application
- `gui.py`: GUI implementation using CustomTkinter
- `sniffer.py`: Core packet sniffing and connection termination logic
- `sniffer_thread.py`: Threading implementation for non-blocking packet capture

## Technical Details

### Packet Handling

The program uses Scapy to:
1. Capture TCP packets on the network
2. Filter packets involving blacklisted IP addresses
3. Generate and send TCP RST packets to terminate unwanted connections

### Threading

The packet sniffing operation runs in a separate thread to:
- Prevent GUI freezing
- Allow real-time updates to the blacklist
- Enable smooth user interaction while monitoring

### GUI Components

- IP input field for blacklist management
- Add/Remove buttons for blacklist modification
- Start/Stop button for sniffing control
- Text display for captured packets and events
- Counter for total packets and terminated connections

## Educational Objectives

This project helps students learn:
1. Understanding of TCP/IP protocols
2. Network packet manipulation with Scapy
3. Python programming for cybersecurity
4. Real-world application of security concepts

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

This project is licensed under the Creative Commons Zero v1.0 Universal License - see the LICENSE file for details.