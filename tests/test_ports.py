from __future__ import annotations

import asyncio
import socket

import pytest

from reconkit.ports import parse_ports, scan_port


class TestParsePorts:
    def test_single(self):
        assert parse_ports("80") == [80]

    def test_list(self):
        assert parse_ports("443,80,8080") == [80, 443, 8080]

    def test_range(self):
        assert parse_ports("10-12") == [10, 11, 12]

    def test_mixed_dedupe_sorted(self):
        assert parse_ports("5-6,6,4") == [4, 5, 6]

    @pytest.mark.parametrize("bad", ["", "abc", "0", "70000", "5-2", "5-", "-3", "1-99999"])
    def test_invalid_raises(self, bad):
        with pytest.raises(ValueError):
            parse_ports(bad)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    return s, port


class TestScanPort:
    def test_open_port_detected(self):
        srv, port = free_port()
        srv.listen(1)
        try:
            open_ = asyncio.run(scan_port("127.0.0.1", port, timeout=1))
            assert open_
        finally:
            srv.close()

    def test_closed_port_detected(self):
        srv, port = free_port()
        port = srv.getsockname()[1]
        srv.close()  # nothing listening now
        open_ = asyncio.run(scan_port("127.0.0.1", port, timeout=0.4))
        assert not open_
