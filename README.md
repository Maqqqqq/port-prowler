# Port Prowler

Port Prowler is a small Python CLI utility for inspecting TCP, UDP, and stealth (SYN) port
responses on a target host.

## Author
- Markus Stamm

## Features

- Flexible port selection: single port, comma-separated list, or ranges (e.g. `20-25`).
- Scan modes: TCP connect, UDP probe, and socket-based stealth scan.
- Multithreading (`-j/--jobs`) for faster scanning of large port sets.
- Structured terminal report with optional `-f/--file` export.

Notes:
- UDP scans may report `Open|Filtered` when no response is received.
- Stealth (`-s/--stealth`) attempts a SYN scan using raw sockets; it may require sudo privileges.
- Optional: `--os` prints a OS guess based on open ports.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

```bash
python -m port_prowler.cli <ip-or-hostname> -p <ports> [options]

Options:
  -p / --ports   Ports to scan (single, comma list, or range)
  -tcp           Enable TCP connect scan
  -udp           Enable UDP scan
  -s / --stealth Enable stealth (half-open) scan
  -f / --file    Save formatted output to the provided path
  -j / --jobs    Number of concurrent threads (default 1)
  --timeout      Socket timeout per probe (seconds, default 1.0)
  --os           Enable lightweight OS guess
```

### Examples

```bash
python -m port_prowler.cli 192.168.1.1 -p 80,443,8080 -tcp
python -m port_prowler.cli 10.0.0.1 -p 20-25 -udp -j 20
python -m port_prowler.cli 172.16.0.1 -p 22 -s -f scan_results.txt
```

## Verification

See `verification.md` and the screenshots in `screenshots/`.
