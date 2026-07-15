# C-Shark: Packet Sniffer

Command-line network packet sniffer that parses and inspects raw pcap captures.

## Files

- `main.c` -- entry point, opens pcap file and drives the parse/inspect loop
- `src/pcap_handler.c` -- reads pcap file header and iterates over packet records
- `src/packet_parser.c` -- parses Ethernet, IP, TCP, UDP, and ICMP headers from raw bytes
- `src/inspector.c` -- protocol-specific inspection and formatted output
- `src/packet_storage.c` -- stores parsed packets for summary/stats
- `src/utils.c` -- helper functions (hex dump, byte swapping)
- `src/colors.h` -- ANSI color codes for terminal output

## Build

```
make
./bin/cshark
```