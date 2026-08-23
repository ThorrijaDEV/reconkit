from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import aiohttp
import pytest

from reconkit.dirs import dirbust


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/admin":
            self.send_response(200)
        elif self.path == "/old":
            self.send_response(301)
            self.send_header("Location", "/new")
            self.end_headers()
        elif self.path == "/secret":
            self.send_response(403)
            self.end_headers()
        else:
            self.send_response(404)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server_url():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def fetch(server_url):
    async def run():
        async with aiohttp.ClientSession() as s:
            return await dirbust(s, server_url)
    return asyncio.run(run())


def test_dirbust_finds_interesting_paths(server_url):
    hits = fetch(server_url)
    by_path = {h.path: h for h in hits}
    assert by_path["/admin"].status == 200
    assert by_path["/old"].status == 301
    assert by_path["/secret"].status == 403
    # nothing with status 404 should ever be reported
    assert all(h.status != 404 for h in hits)
    # sorted: 200s first
    assert hits[0].path == "/admin"


def test_dirbust_trailing_slash_normalized(server_url):
    hits = fetch(server_url + "/")
    assert any(h.path == "/admin" for h in hits)
