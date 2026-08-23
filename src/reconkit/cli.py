from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path
from typing import Optional

import aiohttp

from reconkit import dirs as dirs_mod
from reconkit import ports as ports_mod
from reconkit import subdomains as sub_mod
from reconkit.report import render_report
from reconkit.store import Finding, Store

DEFAULT_DB = Path.home() / ".local" / "state" / "reconkit" / "sessions.db"
DEFAULT_REPORT_DIR = Path("reports")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconkit",
        description="Reconnaissance multi-tool for assets you own or are authorized to test.",
    )
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--session", metavar="ID", help="append to an existing session")
    parser.add_argument("--note", default="", help="label stored with a new session")
    sub = parser.add_subparsers(dest="command", required=True)

    p_sub = sub.add_parser("subdomains", help="enumerate subdomains via CT logs (crt.sh)")
    p_sub.add_argument("domain")

    p_ports = sub.add_parser("ports", help="async TCP connect scan")
    p_ports.add_argument("host")
    p_ports.add_argument("--top", action="store_true", help="curated common-port list (default)")
    p_ports.add_argument("-p", "--port-spec", default=None,
                         help="e.g. 80 | 80,443 | 1-1024 (overrides --top)")
    p_ports.add_argument("--timeout", type=float, default=1.5)
    p_ports.add_argument("--concurrency", type=int, default=512)

    p_dirs = sub.add_parser("dirs", help="discover paths on a web server")
    p_dirs.add_argument("url", help="base URL, e.g. http://host:8080")
    p_dirs.add_argument("--concurrency", type=int, default=16)

    p_report = sub.add_parser("report", help="render the session as a standalone HTML report")
    p_report.add_argument("--out", type=Path, default=None, help="output file (default reports/<id>.html)")

    p_sessions = sub.add_parser("sessions", help="list recorded sessions")
    return parser


def _resolve_session(args, store: Store) -> str:
    if args.session:
        return args.session
    sid = store.new_session(note=args.note)
    print(f"[session {sid}]")
    return sid


def cmd_subdomains(args, store: Store, sid: str) -> int:
    async def run():
        async with aiohttp.ClientSession() as http:
            try:
                found = await sub_mod.fetch_subdomains(http, args.domain)
            except aiohttp.ClientError as exc:
                print(f"error: crt.sh no respondió ({exc})", file=sys.stderr)
                return 1
        for host in found:
            store.add(sid, Finding(module="subdomains", target=args.domain,
                                   value=host, detail="crt.sh"))
        store.commit()
        print(f"{len(found)} subdominio(s) de {args.domain}")
        for host in found[:25]:
            print(f"  {host}")
        if len(found) > 25:
            print(f"  … y {len(found) - 25} más (guardados en la sesión)")
        return 0

    return asyncio.run(run())


def cmd_ports(args, store: Store, sid: str) -> int:
    if args.port_spec:
        try:
            port_list = ports_mod.parse_ports(args.port_spec)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        port_list = list(ports_mod.COMMON_PORTS)

    total = len(port_list)
    print(f"Escaneando {args.host}: {total} puertos…")
    last = [0.0]

    def progress(done: int):
        now = time.time()
        if now - last[0] > 0.5:
            last[0] = now
            print(f"  {done}/{total}", end="\r", flush=True)

    open_ports = asyncio.run(
        ports_mod.scan_ports(args.host, port_list,
                             concurrency=args.concurrency,
                             timeout=args.timeout,
                             progress=progress),
    )
    print(" " * 24, end="\r")
    for port in open_ports:
        service = ports_mod.SERVICE_HINTS.get(port, "?")
        print(f"  {port:>5}/tcp abierto  [{service}]")
        store.add(sid, Finding(module="ports", target=args.host,
                               value=f"{port}/tcp", detail=service))
    store.commit()
    print(f"{len(open_ports)} puerto(s) abierto(s) de {total}")
    return 0


def cmd_dirs(args, store: Store, sid: str) -> int:
    async def run():
        async with aiohttp.ClientSession() as http:
            return await dirs_mod.dirbust(http, args.url)

    hits = asyncio.run(run())
    for hit in hits:
        print(f"  {hit.status} {hit.path:<28} {hit.size:>8} B")
        store.add(sid, Finding(module="dirs", target=args.url.rstrip("/"),
                               value=hit.path, detail=str(hit.status)))
    store.commit()
    print(f"{len(hits)} ruta(s) interesante(s)")
    return 0


def cmd_report(args, store: Store, sid: str) -> int:
    row = store.conn.execute("SELECT started, note FROM sessions WHERE id = ?", (sid,)).fetchone()
    if row is None:
        print(f"error: sesión desconocida: {sid}", file=sys.stderr)
        return 2
    started, note = row
    by_module = {
        m: store.findings(sid, module=m) for m in ("subdomains", "ports", "dirs")
    }
    out = args.out or (DEFAULT_REPORT_DIR / f"{sid}.html")
    path = render_report(sid, started, note, by_module, out)
    total = sum(len(v) for v in by_module.values())
    print(f"Informe con {total} hallazgo(s): {path}")
    return 0


def cmd_sessions(args, store: Store) -> int:
    sessions = store.sessions()
    if not sessions:
        print("Sin sesiones todavía.")
        return 0
    for s in sessions:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(s["started"]))
        print(f"  {s['id']}  {when}  {s['findings']:>4} hallazgos  {s['note']}")
    return 0


COMMANDS = {"subdomains": cmd_subdomains, "ports": cmd_ports, "dirs": cmd_dirs}


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    store = Store(args.db)
    try:
        if args.command == "sessions":
            return cmd_sessions(args, store)
        if args.command == "report":
            sid = getattr(args, "session", None)
            if not sid:
                latest = store.sessions()
                if not latest:
                    print("error: no hay sesiones; ejecuta un módulo primero", file=sys.stderr)
                    return 2
                sid = latest[0]["id"]
            args.session = sid
            return cmd_report(args, store, sid)
        sid = _resolve_session(args, store)
        return COMMANDS[args.command](args, store, sid)
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
