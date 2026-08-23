from __future__ import annotations

from pathlib import Path

from reconkit.report import render_report
from reconkit.store import Finding, Store


def test_store_roundtrip(tmp_path):
    store = Store(tmp_path / "s.db")
    sid = store.new_session(note="prueba")
    store.add(sid, Finding(module="ports", target="h", value="22/tcp", detail="ssh"))
    store.add(sid, Finding(module="dirs", target="u", value="/admin", detail="200"))
    store.commit()

    assert len(store.findings(sid)) == 2
    assert [f.value for f in store.findings(sid, module="ports")] == ["22/tcp"]

    sessions = store.sessions()
    assert sessions[0]["id"] == sid and sessions[0]["findings"] == 2
    store.close()


def test_report_renders_all_modules(tmp_path):
    store = Store(tmp_path / "s.db")
    sid = store.new_session(note="informe")
    store.add(sid, Finding(module="subdomains", target="example.com",
                           value="api.example.com", detail="crt.sh"))
    store.add(sid, Finding(module="ports", target="10.0.0.1", value="443/tcp", detail="https"))
    store.add(sid, Finding(module="dirs", target="http://x", value="/admin", detail="200"))
    store.commit()

    by_module = {m: store.findings(sid, module=m) for m in ("subdomains", "ports", "dirs")}
    out = tmp_path / "rep.html"
    path = render_report(sid, 0.0, "informe", by_module, out)

    html_text = path.read_text(encoding="utf-8")
    assert path == out and out.exists()
    for fragment in ("api.example.com", "443/tcp", "/admin", "Subdominios",
                     "Puertos TCP abiertos", "Rutas descubiertas"):
        assert fragment in html_text


def test_report_empty_session_is_valid_html(tmp_path):
    out = tmp_path / "empty.html"
    path = render_report("abc123", 0.0, "", {}, out)
    text = path.read_text()
    assert text.startswith("<!DOCTYPE html>") and "Sin resultados" in text
