from __future__ import annotations

import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Finding:
    module: str          # subdomains | ports | dirs
    target: str
    value: str           # subdomain host / "port/80 open" / discovered path
    detail: str = ""     # status code, service banner, title...
    ts: float = field(default_factory=time.time)


class Store:
    """Session store: every run gets an id; findings accumulate per session."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions(
              id TEXT PRIMARY KEY, started REAL NOT NULL, note TEXT);
            CREATE TABLE IF NOT EXISTS findings(
              id INTEGER PRIMARY KEY,
              session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
              ts REAL NOT NULL, module TEXT NOT NULL,
              target TEXT NOT NULL, value TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');
            CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
            """
        )
        self.conn.commit()

    def new_session(self, note: str = "") -> str:
        sid = uuid.uuid4().hex[:8]
        self.conn.execute("INSERT INTO sessions (id, started, note) VALUES (?, ?, ?)",
                          (sid, time.time(), note))
        self.conn.commit()
        return sid

    def add(self, session_id: str, finding: Finding) -> None:
        d = asdict(finding)
        self.conn.execute(
            "INSERT INTO findings (session_id, ts, module, target, value, detail)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, d["ts"], d["module"], d["target"], d["value"], d["detail"]),
        )

    def commit(self) -> None:
        self.conn.commit()

    def findings(self, session_id: str, module: Optional[str] = None) -> list[Finding]:
        sql = "SELECT ts, module, target, value, detail FROM findings WHERE session_id = ?"
        args: list = [session_id]
        if module:
            sql += " AND module = ?"
            args.append(module)
        sql += " ORDER BY id"
        return [
            Finding(module=m, target=t, value=v, detail=dt, ts=ts)
            for ts, m, t, v, dt in self.conn.execute(sql, args)
        ]

    def sessions(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, started, note,"
            " (SELECT COUNT(*) FROM findings f WHERE f.session_id = s.id) FROM sessions s ORDER BY started DESC"
        ).fetchall()
        return [{"id": r[0], "started": r[1], "note": r[2], "findings": r[3]} for r in rows]

    def close(self):
        self.conn.close()
