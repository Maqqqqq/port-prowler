from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .scanner import PortResult, PortStatus, ScanPlan, ScanReport


def format_results(plan: ScanPlan, report: ScanReport) -> str:

    lines: list[str] = []
    mode_labels = ", ".join(st.name for st in plan.scan_types)
    lines.append(f"Scanning {plan.target} using {mode_labels} mode(s)...")
    lines.append(f"Ports: {', '.join(str(p) for p in plan.ports)}")
    lines.append(f"Parallelism: {plan.parallelism}, Timeout: {plan.timeout:.2f}s")
    lines.append("")
    lines.append(f"{'Port':>6}  {'Scan':<7}  {'Status':<9}  {'Latency(ms)':>12}  Service")
    lines.append("-" * 60)
    for result in report.results:
        latency_ms = f"{(result.latency or 0) * 1000:.2f}" if result.latency else "-"
        service = result.service or "?"
        status = str(result.status)
        if result.status is PortStatus.ERROR and result.error:
            status = f"{status} ({result.error})"
        lines.append(
            f"{result.port:>6}  {result.scan_type.name:<7}  {status:<9}  {latency_ms:>12}  {service}"
        )

    if report.os_guess:
        lines.append("")
        lines.append(f"OS Guess: {report.os_guess}")

    return "\n".join(lines)


def save_results(content: str, destination: str) -> Path:
    target = Path(destination)

    if target.exists():
        stem = target.stem
        suffix = target.suffix
        parent = target.parent
        counter = 1
        while True:
            candidate = parent / f"{stem}{counter}{suffix}"
            if not candidate.exists():
                target = candidate
                break
            counter += 1

    target.write_text(content, encoding="utf-8")
    return target
