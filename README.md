# reconkit

Un multi-tool de reconocimiento ligero para **activos propios o autorizados**: subdominios vía logs de Certificate Transparency, escáner de puertos TCP asíncrono, descubrimiento de rutas web, y un informe HTML unificado por sesión.

```
$ reconkit subdomains ejemplo.com
$ reconkit ports 10.0.0.1 -p 1-1024
$ reconkit dirs http://10.0.0.1:8080
$ reconkit report
Informe con 47 hallazgo(s): reports/a1b2c3d4.html
```

## Por qué

Las herramientas grandes (nmap, ffuf, subfinder) son excelentes pero cada una guarda sus resultados a su manera. `reconkit` es deliberadamente pequeño: tres módulos esenciales que comparten **una sesión SQLite**, y al final un único informe HTML navegable con todo lo encontrado.

## Módulos

| Comando | Qué hace | Técnica |
|---|---|---|
| `subdomains <dominio>` | Enumera subdominios | Logs de CT públicos de [crt.sh](https://crt.sh) (sin API key) |
| `ports <host>` | Puertos TCP abiertos | Connect scan asíncrono (asyncio), lista curada o `-p 80,443,8000-8100` |
| `dirs <url>` | Rutas interesantes en un servidor | Peticiones concurrentes con lista integrada (~50 palabras habituales) |
| `report` | Informe HTML standalone | Todo lo acumulado en la sesión, sin dependencias JS |
| `sessions` | Lista las sesiones guardadas | id · fecha · nº de hallazgos |

Todos los resultados se acumulan en la misma sesión hasta que crees una nueva (`--note "audito X"` para etiquetarla, o `--session <id>` para volver a una anterior).

## Instalación

Python ≥ 3.9; única dependencia: `aiohttp`.

```bash
git clone https://github.com/ThorrijaDEV/reconkit
cd reconkit
python3 -m venv .venv && source .venv/bin/activate
pip install .
reconkit --help
```

## Ejemplo de flujo completo

```bash
reconkit --note "mi servidor casero" subdomains midominio.com
reconkit --session <id> ports servidor.midominio.com --top
reconkit --session <id> dirs https://servidor.midominio.com
reconkit --session <id> report --out mi-auditoria.html
```

El informe clasifica cada módulo en su sección, colorea los códigos HTTP (verde 2xx, ámbar 3xx, rojo 4xx) y cierra con un recordatorio de uso responsable.

## Ética y legalidad

Esta herramienta existe para auditar **tus propios sistemas** o sistemas donde tengas **autorización explícita y por escrito**. Escanear infraestructura ajena es ilegal en la mayoría de jurisdicciones (p. ej. art. 197 CP en España, CFAA en EE. UU.). Los módulos están diseñados para ser discretos (timeouts, concurrencia limitada), no para evadir defensas.

## Limitaciones v0.1

- Connect scan: más lento que SYN scan; sin detección de servicio profunda (solo heurística puerto→nombre).
- crt.sh depende de su disponibilidad; sin wordlists externas todavía.
- Sin export JSON (roadmap).

Roadmap: export JSON/markdown, wordlists propias (`-w`), resolución DNS de subdominios encontrados, capturas con headless chromium, modo TUI.

## Desarrollo

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e . pytest
pytest          # todo offline: parsers con fixtures, sockets locales, http.server real
```

```
src/reconkit/
├── store.py       # sesiones + hallazgos (SQLite)
├── subdomains.py  # crt.sh + parser testeable offline
├── ports.py       # parseo de especificaciones + scan asíncrono
├── dirs.py        # dirbusting concurrente
├── report.py      # plantilla HTML
└── cli.py         # wiring argparse
tests/
```

## Licencia

[MIT](LICENSE)
