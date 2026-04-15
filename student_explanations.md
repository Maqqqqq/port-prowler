# Student Explanations

## What is a computer port?
A port is a numbered endpoint (1–65535) on a host that identifies which network service/application should receive traffic for a given protocol (TCP/UDP). IP gets you to the host; the port gets you to the right service.

## Why do topology + open ports matter in cybersecurity?
Topology tells you what systems exist and how they connect; open ports show which services are exposed. Together they define the attack surface (what can be reached, attacked, or misconfigured) and help prioritize risk.

## What does a port scanner (e.g., Nmap) do?
It probes ports on a target to determine whether they’re open/closed/filtered, often with different techniques (TCP connect, SYN/stealth, UDP). This supports asset discovery, validation of firewall rules, and vulnerability testing.

## How does TCP work and how is it used in port scanning?
TCP is connection-oriented (SYN → SYN/ACK → ACK). A TCP connect scan attempts a full connection; if the connect succeeds the port is open, if it’s refused it’s closed, and if it times out it’s filtered.

## How does UDP work and how is it used in port scanning?
UDP is connectionless (no handshake). Scanners send a UDP datagram and infer state: an ICMP “port unreachable” usually means closed; no response often means open or filtered (UDP services may stay silent).

## What “stealth” technique is used here?
This project’s `-s/--stealth` mode uses a socket “half-open style” approach by setting `SO_LINGER` to send an immediate RST on close after `connect_ex`. It reduces how long the connection stays established, but it is not a true raw-packet SYN scan.

## Differences: TCP vs UDP vs stealth scans
- TCP connect: reliable open/closed signal via the TCP handshake, but more visible in logs.
- UDP scan: harder to classify because silence is ambiguous; relies on ICMP errors/timeouts.
- Stealth (classic SYN): sends SYN and interprets SYN/ACK vs RST without completing the handshake (requires raw packets/privileges). This project approximates “stealth” using TCP socket options rather than raw SYN packets.
