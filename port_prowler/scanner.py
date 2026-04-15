from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
import concurrent.futures
import errno
import random
import socket
import struct
import time
from typing import Iterable, List, Sequence


class ScanType(Enum):
    TCP = auto()
    UDP = auto()
    STEALTH = auto()


class PortStatus(Enum):
    OPEN = "Open"
    CLOSED = "Closed"
    FILTERED = "Filtered"
    OPEN_FILTERED = "Open|Filtered"
    ERROR = "Error"

    def __str__(self) -> str:  # pragma: no cover - simple helper
        return self.value


@dataclass
class PortResult:
    port: int
    scan_type: ScanType
    status: PortStatus
    latency: float | None = None
    service: str | None = None
    error: str | None = None


@dataclass
class ScanPlan:
    target: str
    ports: List[int]
    scan_types: List[ScanType]
    output_file: str | None = None
    parallelism: int = 1
    timeout: float = 1.0
    os_detection: bool = False


@dataclass
class ScanReport:
    results: List[PortResult]
    os_guess: str | None = None


class PortScanner:

    def __init__(self, plan: ScanPlan) -> None:
        self.plan = plan

    def execute(self) -> ScanReport:
        if not self.plan.ports:
            raise ValueError("No ports specified for scanning.")
        if not self.plan.scan_types:
            raise ValueError("No scan types specified.")

        jobs = [
            (port, scan_type)
            for port in self.plan.ports
            for scan_type in self.plan.scan_types
        ]
        max_workers = max(1, self.plan.parallelism)
        results: List[PortResult] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(self._scan_port, port, scan_type): (port, scan_type)
                for port, scan_type in jobs
            }
            for future in concurrent.futures.as_completed(future_map):
                port, scan_type = future_map[future]
                try:
                    results.append(future.result())
                except Exception as exc:  # pragma: no cover - defensive
                    results.append(
                        PortResult(
                            port=port,
                            scan_type=scan_type,
                            status=PortStatus.ERROR,
                            error=str(exc),
                        )
                    )

        results.sort(key=lambda r: (r.port, r.scan_type.value))
        detect_services(results)
        os_guess = detect_operating_system(results) if self.plan.os_detection else None
        return ScanReport(results=results, os_guess=os_guess)

    # ------------------------------------------------------------------
    def _scan_port(self, port: int, scan_type: ScanType) -> PortResult:
        if scan_type is ScanType.TCP:
            return self._scan_tcp(port)
        if scan_type is ScanType.UDP:
            return self._scan_udp(port)
        if scan_type is ScanType.STEALTH:
            return self._scan_stealth(port)
        raise ValueError(f"Unsupported scan type: {scan_type}")

    def _scan_tcp(self, port: int) -> PortResult:
        start = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.plan.timeout)
            result = sock.connect_ex((self.plan.target, port))
        latency = time.perf_counter() - start
        status, error = _interpret_tcp_result(result)
        return PortResult(
            port=port,
            scan_type=ScanType.TCP,
            status=status,
            latency=latency,
            error=error,
        )

    def _scan_udp(self, port: int) -> PortResult:
        start = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.plan.timeout)
            try:
                # Connecting a UDP socket allows ICMP "port unreachable" errors
                # to surface as ECONNREFUSED/ConnectionRefusedError on Linux,
                # matching how tools like Nmap infer closed UDP ports.
                sock.connect((self.plan.target, port))
                sock.send(b"\x00")
                sock.recv(1024)
            except socket.timeout:
                latency = time.perf_counter() - start
                return PortResult(
                    port=port,
                    scan_type=ScanType.UDP,
                    status=PortStatus.OPEN_FILTERED,
                    latency=latency,
                )
            except ConnectionRefusedError:
                latency = time.perf_counter() - start
                return PortResult(
                    port=port,
                    scan_type=ScanType.UDP,
                    status=PortStatus.CLOSED,
                    latency=latency,
                )
            except OSError as exc:
                latency = time.perf_counter() - start
                if exc.errno == errno.ECONNREFUSED:
                    return PortResult(
                        port=port,
                        scan_type=ScanType.UDP,
                        status=PortStatus.CLOSED,
                        latency=latency,
                    )
                return PortResult(
                    port=port,
                    scan_type=ScanType.UDP,
                    status=PortStatus.ERROR,
                    latency=latency,
                    error=str(exc),
                )
        latency = time.perf_counter() - start
        return PortResult(
            port=port,
            scan_type=ScanType.UDP,
            status=PortStatus.OPEN,
            latency=latency,
        )

    def _scan_stealth(self, port: int) -> PortResult:

        try:
            return _syn_scan(
                target=self.plan.target,
                port=port,
                timeout=self.plan.timeout,
            )
        except PermissionError as exc:
            fallback = _stealth_connect_scan(
                target=self.plan.target,
                port=port,
                timeout=self.plan.timeout,
            )
            fallback.error = str(exc)
            return fallback


def parse_ports(port_spec: str) -> List[int]:

    if not port_spec:
        raise ValueError("Port specification cannot be empty.")

    ports: set[int] = set()
    for token in port_spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start_str, end_str = token.split("-", 1)
            start, end = _coerce_port(start_str), _coerce_port(end_str)
            if start > end:
                raise ValueError(f"Invalid port range: {token}")
            ports.update(range(start, end + 1))
        else:
            ports.add(_coerce_port(token))

    if not ports:
        raise ValueError("No ports parsed from specification.")

    return sorted(ports)


def detect_services(results: Iterable[PortResult]) -> None:

    for result in results:
        if result.status is not PortStatus.OPEN or result.service:
            continue
        protocol = "udp" if result.scan_type is ScanType.UDP else "tcp"
        try:
            result.service = socket.getservbyport(result.port, protocol)
        except OSError:
            result.service = None


def detect_operating_system(_results: Iterable[PortResult]) -> str | None:

    open_ports = {r.port for r in _results if r.status is PortStatus.OPEN}
    if not open_ports:
        return None

    heuristics: Sequence[tuple[set[int], str]] = (
        ({135, 139, 445}, "Likely Windows (SMB/RPC ports open)"),
        ({22, 111, 2049}, "Likely Linux/Unix (SSH/NFS ports open)"),
        ({548, 636}, "Likely macOS (AFP/LDAPS ports open)"),
    )

    for required_ports, description in heuristics:
        if required_ports.issubset(open_ports):
            return description

    if 3389 in open_ports:
        return "Likely Windows (RDP detected)"
    if 22 in open_ports:
        return "Likely Unix-like host (SSH detected)"
    return "Insufficient data"


def _coerce_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError(f"Invalid port value: {value}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"Port out of range: {port}")
    return port


def _interpret_tcp_result(result: int) -> tuple[PortStatus, str | None]:
    if result == 0:
        return PortStatus.OPEN, None
    if result in {errno.ECONNREFUSED}:
        return PortStatus.CLOSED, None
    if result in {
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
        errno.ETIMEDOUT,
        errno.EAGAIN,
        getattr(errno, "EWOULDBLOCK", errno.EAGAIN),
    }:
        return PortStatus.FILTERED, errno.errorcode.get(result, "Filtered")
    return PortStatus.ERROR, errno.errorcode.get(result, "Unknown error")


def _stealth_connect_scan(target: str, port: int, timeout: float) -> PortResult:
    """Fallback stealth scan via connect with immediate RST (SO_LINGER)."""

    start = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        linger = struct.pack("ii", 1, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        result = sock.connect_ex((target, port))
    latency = time.perf_counter() - start
    status, error = _interpret_tcp_result(result)
    return PortResult(
        port=port,
        scan_type=ScanType.STEALTH,
        status=status,
        latency=latency,
        error=error,
    )


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for idx in range(0, len(data), 2):
        total += (data[idx] << 8) + data[idx + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _get_source_ip(dest_ip: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((dest_ip, 1))
        return sock.getsockname()[0]


def _syn_scan(target: str, port: int, timeout: float) -> PortResult:

    dest_ip = socket.gethostbyname(target)
    src_ip = _get_source_ip(dest_ip)
    src_port = random.randint(32768, 60999)
    seq = random.randint(0, 0xFFFFFFFF)
    packet_id = random.randint(0, 0xFFFF)

    tcp_offset_res = (5 << 4) + 0
    tcp_flags_syn = 0x02
    tcp_window = socket.htons(5840)
    tcp_urg_ptr = 0
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        port,
        seq,
        0,
        tcp_offset_res,
        tcp_flags_syn,
        tcp_window,
        0,
        tcp_urg_ptr,
    )

    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dest_ip),
        0,
        socket.IPPROTO_TCP,
        len(tcp_header),
    )
    tcp_checksum = _checksum(pseudo_header + tcp_header)
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        port,
        seq,
        0,
        tcp_offset_res,
        tcp_flags_syn,
        tcp_window,
        tcp_checksum,
        tcp_urg_ptr,
    )

    ip_ver_ihl = (4 << 4) + 5
    ip_tos = 0
    ip_total_len = 20 + len(tcp_header)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ver_ihl,
        ip_tos,
        ip_total_len,
        packet_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_check,
        socket.inet_aton(src_ip),
        socket.inet_aton(dest_ip),
    )
    ip_check = _checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ver_ihl,
        ip_tos,
        ip_total_len,
        packet_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_check,
        socket.inet_aton(src_ip),
        socket.inet_aton(dest_ip),
    )

    start = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sender, socket.socket(
        socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
    ) as receiver:
        sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        receiver.settimeout(timeout)

        sender.sendto(ip_header + tcp_header, (dest_ip, 0))

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                packet, _addr = receiver.recvfrom(65535)
            except socket.timeout:
                break

            if len(packet) < 40:
                continue
            ihl = (packet[0] & 0x0F) * 4
            if len(packet) < ihl + 20:
                continue
            ip_src = socket.inet_ntoa(packet[12:16])
            ip_dst = socket.inet_ntoa(packet[16:20])
            if ip_src != dest_ip or ip_dst != src_ip:
                continue
            tcp_segment = packet[ihl : ihl + 20]
            src_p, dst_p, recv_seq, recv_ack, offset_res, flags, *_rest = struct.unpack(
                "!HHLLBBHHH", tcp_segment
            )
            if src_p != port or dst_p != src_port:
                continue

            latency = time.perf_counter() - start
            if flags & 0x12 == 0x12:  # SYN+ACK
                _send_rst(
                    sender=sender,
                    src_ip=src_ip,
                    dest_ip=dest_ip,
                    src_port=src_port,
                    dest_port=port,
                    seq_num=recv_ack,
                    ack_num=recv_seq + 1,
                )
                return PortResult(
                    port=port,
                    scan_type=ScanType.STEALTH,
                    status=PortStatus.OPEN,
                    latency=latency,
                )
            if flags & 0x04:  # RST
                return PortResult(
                    port=port,
                    scan_type=ScanType.STEALTH,
                    status=PortStatus.CLOSED,
                    latency=latency,
                )

    latency = time.perf_counter() - start
    return PortResult(
        port=port,
        scan_type=ScanType.STEALTH,
        status=PortStatus.FILTERED,
        latency=latency,
    )


def _send_rst(
    *,
    sender: socket.socket,
    src_ip: str,
    dest_ip: str,
    src_port: int,
    dest_port: int,
    seq_num: int,
    ack_num: int,
) -> None:
    tcp_offset_res = (5 << 4) + 0
    flags = 0x14  # RST + ACK
    tcp_window = socket.htons(0)
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dest_port,
        seq_num & 0xFFFFFFFF,
        ack_num & 0xFFFFFFFF,
        tcp_offset_res,
        flags,
        tcp_window,
        0,
        0,
    )
    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dest_ip),
        0,
        socket.IPPROTO_TCP,
        len(tcp_header),
    )
    tcp_checksum = _checksum(pseudo_header + tcp_header)
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dest_port,
        seq_num & 0xFFFFFFFF,
        ack_num & 0xFFFFFFFF,
        tcp_offset_res,
        flags,
        tcp_window,
        tcp_checksum,
        0,
    )

    packet_id = random.randint(0, 0xFFFF)
    ip_ver_ihl = (4 << 4) + 5
    ip_tos = 0
    ip_total_len = 20 + len(tcp_header)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ver_ihl,
        ip_tos,
        ip_total_len,
        packet_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dest_ip),
    )
    ip_check = _checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ver_ihl,
        ip_tos,
        ip_total_len,
        packet_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_check,
        socket.inet_aton(src_ip),
        socket.inet_aton(dest_ip),
    )

    sender.sendto(ip_header + tcp_header, (dest_ip, 0))
