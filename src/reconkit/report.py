from __future__ import annotations

import html
import time
from pathlib import Path

from reconkit.store import Finding

MODULE_TITLES = {
    "subdomains": "Subdominios (CT logs)",
    "ports": "Puertos TCP abiertos",
    "dirs": "Rutas descubiertas",
}

_CSS = """
body{font:15px/1.6 -apple-system,'Segoe UI',sans-serif;color:#1d1d1f;background:#f5f5f7;margin:0;padding:40px 16px}
main{max-width:860px;margin:0 auto}
h1{font-size:26px;letter-spacing:-.02em}h1 span{color:#0066cc}
.meta{color:#6e6e73;font-size:13px;margin-bottom:28px}
section{background:#fff;border-radius:14px;padding:22px 24px;margin-bottom:18px;
  box-shadow:0 1px 3px rgba(0,0,0,.06)}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.08em;color:#6e6e73;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:14px}
td,th{text-align:left;padding:7px 10px;border-bottom:1px solid #eee}
th{color:#86868b;font-weight:600;font-size:12px;text-transform:uppercase}
code{background:#f5f5f7;border-radius:4px;padding:1px 6px;font-size:13px}
.s200{color:#1a7f37;font-weight:600}.s3xx{color:#9a6700;font-weight:600}.s4xx{color:#cf222e;font-weight:600}
.empty{color:#86868b;font-style:italic}
footer{color:#86868b;font-size:12px;margin-top:26px;text-align:center}
"""


def render_report(
    session_id: str,
    started: float,
    note: str,
    findings_by_module: dict[str, list[Finding]],
    out_path: Path,
) -> Path:
    parts = [
        "<!DOCTYPE html><html lang='es'><head><meta charset='utf-8'>",
        f"<title>reconkit — {html.escape(session_id)}</title>",
        f"<style>{_CSS}</style></head><body><main>",
        "<h1>recon<span>kit</span> · informe</h1>",
        f"<p class='meta'>Sesión <code>{html.escape(session_id)}</code> · "
        f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(started))}"
        + (f" · {html.escape(note)}" if note else "")
        + "</p>",
    ]

    for module in ("subdomains", "ports", "dirs"):
        items = findings_by_module.get(module, [])
        parts.append(f"<section><h2>{MODULE_TITLES[module]} · {len(items)}</h2>")
        if not items:
            parts.append("<p class='empty'>Sin resultados en este módulo.</p></section>")
            continue
        rows = []
        for f in items:
            detail_class = ""
            if module == "dirs" and f.detail.startswith("20"):
                detail_class = " class='s200'"
            elif module == "dirs" and f.detail.startswith("3"):
                detail_class = " class='s3xx'"
            elif module == "dirs" and f.detail.startswith("4"):
                detail_class = " class='s4xx'"
            value = html.escape(f.value)
            detail = html.escape(f.detail)
            if module == "dirs":
                rows.append(
                    f"<tr><td><code>{value}</code></td><td{detail_class}>{detail}</td>"
                    f"<td>{html.escape(f.target)}</td></tr>"
                )
            elif module == "subdomains":
                rows.append(f"<tr><td><code>{value}</code></td><td>{detail}</td></tr>")
            else:
                rows.append(f"<tr><td>{value}</td><td>{detail}</td></tr>")
        header = {
            "dirs": "<tr><th>Ruta</th><th>Estado</th><th>Objetivo</th></tr>",
            "subdomains": "<tr><th>Host</th><th>Fuente</th></tr>",
            "ports": "<tr><th>Puerto</th><th>Servicio</th></tr>",
        }[module]
        parts.append(f"<table>{header}{''.join(rows)}</table></section>")

    parts.append(
        "<footer>Generado por reconkit — úsalo solo en activos que te pertenezcan"
        " o para los que tengas autorización explícita.</footer>"
    )
    parts.append("</main></body></html>")

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(parts), encoding="utf-8")
    return out_path
