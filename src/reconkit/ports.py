from __future__ import annotations

import asyncio
import socket
from typing import Iterable

# Curated set: admin panels, web, mail, db, dev servers.
COMMON_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 3000, 3306, 3389, 5000, 5432, 5900, 6379,
    8000, 8080, 8081, 8443, 8888, 9000, 9200, 11211, 27017,
)

SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}


def parse_ports(spec: str) -> list[int]:
    """'80' | '80,443,8080' | '1-1024' | mixes thereof → sorted unique list."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            if not (lo.isdigit() and hi.isdigit()):
                raise ValueError(f"invalid port range: {part!r}")
            lo, hi = int(lo), int(hi)
            if not (0 < lo <= hi <= 65535):
                raise ValueError(f"port range out of bounds: {part!r}")
            ports.update(range(lo, hi + 1))
        elif part.isdigit():
            p = int(part)
            if not (0 < p <= 65535):
                raise ValueError(f"port out of bounds: {part!r}")
            ports.add(p)
        else:
            raise ValueError(f"invalid port spec: {part!r}")
    return sorted(ports)


async def scan_port(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def scan_ports(
    host: str,
    ports: Iterable[int],
    concurrency: int = 512,
    timeout: float = 1.5,
    progress=None,
) -> list[int]:
    """Concurrent TCP connect scan; returns open ports ascending."""
    sem = asyncio.Semaphore(concurrency)
    open_ports: list[int] = []
    done = 0

    async def worker(port: int):
        nonlocal done
        async with sem:
            if await scan_port(host, port, timeout):
                open_ports.append(port)
            done += 1
            if progress and done % 64 == 0:
                progress(done)

    resolved = await asyncio.get_event_loop().getaddrinfo(host, None)
    ip = resolved[0][4][0]

    await asyncio.gather(*(worker(p) for p in ports))
    return sorted(open_ports)
