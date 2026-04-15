from __future__ import annotations

import argparse
from typing import List

from . import __version__
from . import output as output_mod
from . import scanner

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port_prowler.py",
        description="Scan TCP/UDP ports and report their status.",
    )
    parser.add_argument("ip", help="Target IP address or hostname to scan.")
    parser.add_argument(
        "-p",
        "--ports",
        dest="ports",
        required=False,
        help="Port(s) to scan (single, comma-separated list, or range).",
    )
    parser.add_argument("-tcp", action="store_true", help="Enable TCP scan mode.")
    parser.add_argument("-udp", action="store_true", help="Enable UDP scan mode.")
    parser.add_argument(
        "-s",
        "--stealth",
        action="store_true",
        help="Enable stealth scan mode.",
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="output_file",
        help="Write results to the given file path.",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        dest="parallelism",
        type=int,
        default=1,
        help="Number of concurrent worker threads to use.",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=float,
        default=1.0,
        help="Socket timeout in seconds for each probe (default: 1.0).",
    )
    parser.add_argument(
        "--os",
        dest="os_detection",
        action="store_true",
        help="Enable lightweight OS guess based on open ports.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Port Prowler {__version__}",
    )
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not any([args.tcp, args.udp, args.stealth]):
        parser.error("Select at least one scan mode: -tcp, -udp, or -s.")

    if not args.ports:
        parser.error("Specify ports to scan with -p.")

    if args.parallelism < 1:
        parser.error("-j/--jobs must be >= 1.")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero.")

    try:
        ports = scanner.parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    scan_types: List[scanner.ScanType] = []
    if args.tcp:
        scan_types.append(scanner.ScanType.TCP)
    if args.udp:
        scan_types.append(scanner.ScanType.UDP)
    if args.stealth:
        scan_types.append(scanner.ScanType.STEALTH)

    plan = scanner.ScanPlan(
        target=args.ip,
        ports=ports,
        scan_types=scan_types,
        output_file=args.output_file,
        parallelism=args.parallelism,
        timeout=args.timeout,
        os_detection=args.os_detection,
    )

    port_scanner = scanner.PortScanner(plan)
    report = port_scanner.execute()

    content = output_mod.format_results(plan, report)
    print(content)

    if args.output_file:
        saved_path = output_mod.save_results(content, args.output_file)
        print(f"Result written to file: {saved_path}")

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
