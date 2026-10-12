"""OpenSOC Portable: importación y consolidación local, sin ejecución de escaneos."""
from __future__ import annotations
from email.parser import BytesParser
from email.policy import default
import hashlib
import html
import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
from privacy import shared_report

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get("OPENSOC_DATA_DIR", str(ROOT / "data"))).resolve()
IMPORTS = DATA / "imports"
MAX_BYTES = 5 * 1024 * 1024
HOST = "127.0.0.1"
PORT = int(os.environ.get("OPENSOC_PORT", "8770"))


def observations(document):
    """Devuelve observaciones de varios esquemas sin fabricar hallazgos."""
    if not isinstance(document, dict):
        return []
    candidates = [document, document.get("results"), document.get("data")]
    for obj in candidates:
        if isinstance(obj, str):
            try:
                obj = json.loads(obj)
            except (ValueError, TypeError):
                continue
        if isinstance(obj, dict):
            for key in ("observations", "findings", "hallazgos"):
                value = obj.get(key)
                if isinstance(value, list):
                    return [x for x in value if isinstance(x, dict)]
    return []


def identity(item):
    """Deduplicación conservadora: motor, título y evidencia; sin perder variaciones."""
    title = str(item.get("title") or item.get("name") or item.get("finding") or item.get("hallazgo") or "")
    engine = str(item.get("engine") or item.get("motor") or "")
    detail = str(item.get("detail") or item.get("evidence") or item.get("detalle") or "")
    return (engine.strip().casefold(), title.strip().casefold(), detail.strip().casefold())


def consolidate(documents):
    merged = {}
    for source, doc in documents:
        for item in observations(doc):
            key = identity(item)
            if key == ("", "", ""):
                continue
            if key not in merged:
                merged[key] = {"observation": item, "sources": []}
            if source not in merged[key]["sources"]:
                merged[key]["sources"].append(source)
    return list(merged.values())


def load_documents():
    IMPORTS.mkdir(parents=True, exist_ok=True)
    result = []
    for path in sorted(IMPORTS.glob("*.json")):
        try:
            with path.open(encoding="utf-8") as f:
                doc = json.load(f)
            result.append((path.stem, doc))
        except (OSError, ValueError):
            continue
    return result


def render():
    docs = load_documents()
    merged = consolidate(docs)
    rows = []
    for entry in merged:
        o = entry["observation"]
        title = o.get("title") or o.get("name") or o.get("finding") or o.get("hallazgo") or "(sin título)"
        detail = o.get("detail") or o.get("evidence") or o.get("detalle") or ""
        sev = o.get("severity") or o.get("severidad") or "sin clasificar"
        cells = (sev, title, detail, ", ".join(entry["sources"]))
        rows.append("<tr>" + "".join("<td>" + html.escape(str(v)) + "</td>" for v in cells) + "</tr>")
    return """<!doctype html><html lang="es"><meta charset="utf-8">
<title>OpenSOC Portable</title><style>body{font:16px system-ui;background:#0b1424;color:#edf2fb;max-width:1100px;margin:40px auto;padding:20px}
section{background:#192a40;padding:22px;border-radius:12px;margin:18px 0}
input,button{padding:10px}table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #45556a;padding:10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
a{color:#87c5ff}</style><h1>OpenSOC Portable</h1>
<p>Consolidación local de evidencias · Sin escaneos ni extracción de credenciales</p>
<section><h2>Importar JSON de Offensive AI</h2><form action="/import" method="post" enctype="multipart/form-data">
<input type="file" name="report" accept=".json,application/json" required><button>Importar</button></form></section>
<section><h2>Resumen</h2><p>Fuentes: """ + str(len(docs)) + """ · Observaciones únicas: """ + str(len(merged)) + """</p>
<p><a href="/report.json">Exportar JSON técnico (confidencial)</a> · <a href="/report-shared.json">Exportar JSON compartible (redactado)</a> · <a href="/report.html">Informe HTML</a></p>
<table><tr><th>Severidad</th><th>Observación</th><th>Evidencia</th><th>Fuentes</th></tr>""" + "".join(rows) + """</table></section></html>"""


class Handler(BaseHTTPRequestHandler):
    def send_data(self, status, content, typ="text/html; charset=utf-8"):
        raw = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", typ)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            return self.send_data(200, render())
        if path == "/report.html":
            return self.send_data(200, render())
        if path == "/report.json":
            docs = load_documents()
            body = {"sources": [name for name, _ in docs], "unique_observations": consolidate(docs)}
            return self.send_data(200, json.dumps(body, ensure_ascii=False, indent=2), "application/json; charset=utf-8")
        if path == "/report-shared.json":
            docs = load_documents()
            params = parse_qs(urlsplit(self.path).query)
            sections = params.get("section", ["findings", "remediation"])
            include_identifiers = params.get("identifiers", ["no"]) == ["yes"]
            body = shared_report({"sources": [name for name, _ in docs],
                                  "unique_observations": consolidate(docs)},
                                 sections=sections, include_identifiers=include_identifiers)
            return self.send_data(200, json.dumps(body, ensure_ascii=False, indent=2), "application/json; charset=utf-8")
        return self.send_data(404, "No encontrado")

    def do_POST(self):
        if urlsplit(self.path).path != "/import":
            return self.send_data(404, "No encontrado")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.send_data(400, "Longitud inválida")
        if length <= 0 or length > MAX_BYTES:
            return self.send_data(413, "Archivo demasiado grande")
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data;"):
            return self.send_data(415, "Se requiere formulario multipart")
        try:
            payload = self.rfile.read(length)
            message = BytesParser(policy=default).parsebytes(
                ("MIME-Version: 1.0\\r\\nContent-Type: " + content_type +
                 "\\r\\n\\r\\n").replace("\\r", "\r").replace("\\n", "\n").encode("utf-8") + payload
            )
            if not message.is_multipart():
                raise ValueError("Formulario multipart inválido")
            parts = [p for p in message.iter_parts()
                     if p.get_param("name", header="content-disposition") == "report"]
            if len(parts) != 1:
                raise ValueError("Falta el archivo")
            raw = parts[0].get_payload(decode=True)
            if not isinstance(raw, bytes):
                raise ValueError("Archivo inválido")
            if len(raw) > MAX_BYTES:
                return self.send_data(413, "Archivo demasiado grande")
            doc = json.loads(raw.decode("utf-8"))
            if not isinstance(doc, dict) or not observations(doc):
                return self.send_data(422, "JSON válido, pero sin observaciones reconocidas. No se importó.")
            IMPORTS.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256(raw).hexdigest()
            target = IMPORTS / (digest + ".json")
            if not target.exists():
                with target.open("xb") as f:
                    f.write(raw)
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        except (ValueError, KeyError, UnicodeDecodeError, TypeError) as exc:
            self.send_data(400, "No se pudo importar: " + html.escape(str(exc)))


if __name__ == "__main__":
    IMPORTS.mkdir(parents=True, exist_ok=True)
    print(f"OpenSOC Portable: http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
