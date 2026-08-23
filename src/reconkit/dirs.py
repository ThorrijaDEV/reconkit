from __future__ import annotations

import asyncio
from dataclasses import dataclass

import aiohttp

UA = "reconkit/0.1 (+authorized security assessment)"

# Small built-in list: enough to find the usual suspects without a wordlist file.
BUILTIN_WORDS = (
    "admin", "administrator", "api", "app", "backup", "blog", "cgi-bin",
    "config", "dashboard", "db", "dev", "docs", "download", "downloads",
    "email", "files", "ftp", "home", "img", "images", "js", "login",
    "logout", "mail", "media", "new", "old", "panel", "phpmyadmin",
    "private", "public", "register", "robots.txt", "secret", "server-status",
    "sitemap.xml", "src", "static", "staging", "temp", "test", "tmp",
    "uploads", "user", "v1", "v2", "webadmin", "wp-admin", "wp-login.php",
    ".git", ".env", ".htaccess", "favicon.ico",
)

INTERESTING = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405}


@dataclass
class DirHit:
    path: str
    status: int
    size: int


async def dirbust(
    session: aiohttp.ClientSession,
    base_url: str,
    words: tuple[str, ...] = BUILTIN_WORDS,
    concurrency: int = 16,
    timeout: float = 8.0,
) -> list[DirHit]:
    """Probe <base>/<word>; report responses worth a second look."""
    if not base_url.endswith("/"):
        base_url += "/"
    sem = asyncio.Semaphore(concurrency)
    hits: list[DirHit] = []
    lock = asyncio.Lock()

    async def probe(word: str):
        url = base_url + word
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"User-Agent": UA},
                allow_redirects=False,
            ) as resp:
                body = await resp.read()
                if resp.status in INTERESTING:
                    hit = DirHit(path="/" + word, status=resp.status, size=len(body))
                    async with lock:
                        hits.append(hit)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

    await asyncio.gather(*(probe(w) for w in words))
    return sorted(hits, key=lambda h: (h.status != 200, h.path))
