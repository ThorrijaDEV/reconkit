from __future__ import annotations

import asyncio
import json
from typing import Optional

import aiohttp

CTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"

UA = "reconkit/0.1 (+authorized security assessment)"


async def fetch_subdomains(
    session: aiohttp.ClientSession,
    domain: str,
    timeout: float = 30.0,
    retries: int = 3,
) -> list[str]:
    """Subdomains for `domain` from certificate transparency logs (crt.sh).

    crt.sh is famously intermittent: retry with a short backoff.
    """
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            async with session.get(
                CTSH_URL.format(domain=domain),
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"User-Agent": UA},
            ) as resp:
                resp.raise_for_status()
                text = await resp.text()
            return parse_ctsh_json(text, domain)
        except aiohttp.ClientError as exc:
            last_error = exc
            await asyncio.sleep(1.5 * (attempt + 1))
    raise last_error if last_error else RuntimeError("crt.sh failed")


def parse_ctsh_json(text: str, domain: str) -> list[str]:
    """Offline-testable parser: unique names ending with the domain."""
    data = json.loads(text)
    found: set[str] = set()
    suffix = "." + domain.lower()
    for entry in data:
        raw = entry.get("name_value", "")
        for line in str(raw).splitlines():
            name = line.strip().lstrip("*.").lower()
            if name.endswith(suffix) or name == domain.lower():
                # keep only names that belong to this exact domain
                if "*" not in name and " " not in name:
                    found.add(name)
    return sorted(found)
