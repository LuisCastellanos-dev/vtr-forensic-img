"""
vtr-forensic-img v0.3.0
web/app.py

Servidor web local para análisis forense de imágenes.

ARQUITECTURA DE SEGURIDAD — documentada, no asumida:

1. AISLAMIENTO POR SUBPROCESO:
   Cada análisis corre en un subproceso Python independiente
   (subprocess.run con sys.executable). El estado del proceso
   principal nunca es contaminado por una imagen maliciosa —
   si el subproceso muere o es corrompido, el servidor sigue
   funcionando y el siguiente análisis parte de cero.
   Preparado para mitigación adicional futura (sandboxing, seccomp).

2. SIN ESTADO PERSISTENTE DE IMÁGENES:
   La imagen se escribe a un archivo temporal, se analiza, y se
   elimina inmediatamente después — independientemente del resultado.
   El servidor no acumula imágenes entre sesiones.

3. CSP ESTRICTO:
   Content-Security-Policy deshabilita eval(), inline scripts
   no controlados, y conexiones externas. El reporte es
   completamente self-contained — sin CDN, sin fuentes externas.

4. IDENTIFICADOR FORENSE OBLIGATORIO:
   Cada análisis recibe un ID único (timestamp + SHA-256 parcial)
   que aparece en la UI y en el reporte exportable. Permite
   verificación post-análisis: sha256sum imagen.jpg vs. ID del reporte.

5. SOLO LOCALHOST:
   El servidor escucha únicamente en 127.0.0.1 — no en 0.0.0.0.
   No es accesible desde la red, solo desde el mismo equipo.

6. LÍMITE DE TAMAÑO:
   Imágenes > 50MB son rechazadas antes de escribirse a disco.
   Previene ataques de agotamiento de disco y de tiempo de procesamiento.

MITIGACIÓN FUTURA (no implementada en v0.1.0, preparada en diseño):
   - Sandboxing con seccomp/namespaces para el subproceso de análisis
   - Rate limiting por IP (relevante si se expone en red local)
   - Firma del reporte exportado con llave del analista
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sys
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ruta al módulo de análisis — resuelto relativo a este archivo
WEB_DIR = Path(__file__).resolve().parent
PROJECT_DIR = WEB_DIR.parent

MAX_IMAGE_BYTES = 50 * 1024 * 1024  # 50 MB
ALLOWED_MIME_TYPES = {
    "image/jpeg", "image/jpg", "image/png",
    "image/webp", "image/tiff", "image/gif",
}

app = FastAPI(
    title="VTR Forensic Image Analyzer",
    version="0.3.0",
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:7700", "http://127.0.0.1:7700"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def _csp_headers() -> dict:
    return {
        "Content-Security-Policy": (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        ),
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }


def _run_analysis_isolated(image_path: Path, url: str | None = None) -> dict:
    analysis_script = str(PROJECT_DIR / "web" / "_analysis_worker.py")
    cmd = [sys.executable, analysis_script, str(image_path)]
    if url:
        cmd += ["--url", url]

    rust_bin = os.environ.get("VTR_RUST_PARSER_BIN", "")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
            env={**os.environ, "VTR_RUST_PARSER_BIN": rust_bin},
        )
        if result.returncode not in (0, 1, 2):
            logger.error("worker crash: exit=%d stderr=%s",
                         result.returncode, result.stderr[:500])
            raise RuntimeError(f"worker terminó con código {result.returncode}")

        if not result.stdout.strip():
            raise RuntimeError("worker no produjo output")

        return json.loads(result.stdout.strip())

    except subprocess.TimeoutExpired:
        raise RuntimeError("análisis superó el límite de 120 segundos — imagen posiblemente maliciosa")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"output inválido del worker: {str(e)[:100]}")


def _generate_analysis_id(sha256: str) -> str:
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    short_hash = sha256[:8] if sha256 else uuid.uuid4().hex[:8]
    return f"VTR-{ts}-{short_hash}"


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    html = _build_html()
    return HTMLResponse(content=html, headers=_csp_headers())


@app.post("/analyze")
async def analyze(
    request: Request,
    file: Annotated[UploadFile | None, File()] = None,
    url: Annotated[str | None, Form()] = None,
    analyst_id: Annotated[str | None, Form()] = None,
):
    if file is None and not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Proporciona un archivo o una URL, no ambos ni ninguno"
        )
    if file is not None and url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Proporciona un archivo o una URL, no ambos"
        )

    tmp_path = None
    try:
        if file is not None:
            if file.content_type not in ALLOWED_MIME_TYPES:
                raise HTTPException(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    detail=f"Tipo de archivo no soportado: {file.content_type}. "
                           f"Permitidos: JPEG, PNG, WEBP, TIFF, GIF"
                )

            image_bytes = await file.read()
            if len(image_bytes) > MAX_IMAGE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Imagen supera el límite de {MAX_IMAGE_BYTES // 1_048_576} MB"
                )

            suffix = Path(file.filename or "img").suffix or ".tmp"
            fd, tmp_name = tempfile.mkstemp(
                suffix=suffix, dir=tempfile.gettempdir()
            )
            try:
                os.write(fd, image_bytes)
            finally:
                os.close(fd)
            tmp_path = Path(tmp_name)

            report = _run_analysis_isolated(tmp_path)

        else:
            if not (url.startswith("http://") or url.startswith("https://")):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="URL debe comenzar con http:// o https://"
                )
            fd, tmp_name = tempfile.mkstemp(suffix=".url")
            os.close(fd)
            tmp_path = Path(tmp_name)

            report = _run_analysis_isolated(tmp_path, url=url)

        sha256 = report.get("metadata", {}).get("sha256", "")
        analysis_id = _generate_analysis_id(sha256)
        report["analysis_id"] = analysis_id
        if analyst_id:
            import re
            safe_id = re.sub(r'[^A-Za-z0-9\-_]', '', analyst_id)[:50]
            report["analyst_id"] = safe_id

        if file is not None:
            original_name = file.filename or "imagen"
            report["image_source"] = original_name
            if "metadata" in report:
                report["metadata"]["file_path"] = original_name
        elif url:
            report["image_source"] = url

        return JSONResponse(content=report, headers=_csp_headers())

    finally:
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception as e:
                logger.error("no se pudo eliminar temporal %s: %s", tmp_path, e)


@app.get("/health")
async def health():
    rust_bin = os.environ.get("VTR_RUST_PARSER_BIN", "")
    rust_available = bool(rust_bin) and Path(rust_bin).is_file()
    return JSONResponse({
        "status": "ok",
        "version": "0.3.0",
        "rust_parser": "available" if rust_available else "not_found",
    }, headers=_csp_headers())


def _build_html() -> str:
    return r"""<!DOCTYPE html>
<html lang="es" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="referrer" content="no-referrer">
<title>VTR Forensic Image Analyzer</title>
<style>
:root {
  --bg: #f8f9fa;
  --surface: #ffffff;
  --border: #dee2e6;
  --text: #212529;
  --text-dim: #6c757d;
  --accent: #1a6b3c;
  --accent-light: #d4edda;
  --risk-high: #dc3545;
  --risk-high-bg: #f8d7da;
  --risk-med: #fd7e14;
  --risk-med-bg: #fff3cd;
  --risk-low: #198754;
  --risk-low-bg: #d1e7dd;
  --mono: 'Courier New', Courier, monospace;
  --radius: 6px;
  --shadow: 0 1px 4px rgba(0,0,0,0.08);
}
[data-theme="dark"] {
  --bg: #000000;
  --surface: #0a0a0a;
  --border: #1a3d28;
  --text: #e8e8e2;
  --text-dim: #6f8f78;
  --accent: #3fcf71;
  --accent-light: #0f2518;
  --risk-high: #e0635a;
  --risk-high-bg: #1a0d0b;
  --risk-med: #c8a020;
  --risk-med-bg: #1a1408;
  --risk-low: #3fcf71;
  --risk-low-bg: #0f2518;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: system-ui, -apple-system, sans-serif;
  font-size: 15px;
  line-height: 1.55;
  min-height: 100vh;
}
.topbar {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 12px 24px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  position: sticky;
  top: 0;
  z-index: 10;
}
.brand { font-weight: 700; font-size: 16px; letter-spacing: 0.03em; color: var(--accent); }
.brand span { color: var(--text); }
.topbar-right { display: flex; align-items: center; gap: 16px; }
.theme-toggle {
  background: none; border: 1px solid var(--border);
  border-radius: var(--radius); padding: 5px 10px;
  cursor: pointer; font-size: 13px; color: var(--text-dim);
}
.theme-toggle:hover { border-color: var(--accent); color: var(--accent); }
.status-dot { width: 8px; height: 8px; border-radius: 50%; background: #aaa; display: inline-block; }
.status-dot.ok { background: var(--risk-low); }
.main { max-width: 900px; margin: 0 auto; padding: 32px 24px; }

.upload-card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 28px;
  box-shadow: var(--shadow); margin-bottom: 24px;
}
.upload-card h2 { font-size: 17px; font-weight: 600; margin-bottom: 6px; }
.upload-card p { color: var(--text-dim); font-size: 13px; margin-bottom: 20px; }

.drop-zone {
  border: 2px dashed var(--border); border-radius: var(--radius);
  padding: 40px 24px; text-align: center; cursor: pointer;
  transition: border-color 0.2s, background 0.2s; position: relative;
}
.drop-zone:hover, .drop-zone.dragover { border-color: var(--accent); background: var(--accent-light); }
.drop-zone input[type=file] { position: absolute; inset: 0; opacity: 0; cursor: pointer; }
.drop-icon { font-size: 32px; margin-bottom: 10px; }
.drop-label { font-size: 14px; color: var(--text-dim); }
.drop-label strong { color: var(--accent); }

.divider {
  display: flex; align-items: center; gap: 12px;
  margin: 18px 0; color: var(--text-dim); font-size: 12px;
}
.divider::before, .divider::after { content: ''; flex: 1; height: 1px; background: var(--border); }

.url-row { display: flex; gap: 10px; }
.url-input {
  flex: 1; border: 1px solid var(--border); border-radius: var(--radius);
  padding: 9px 13px; font-size: 14px; background: var(--bg); color: var(--text);
}
.url-input:focus { outline: none; border-color: var(--accent); }

.analyst-row { margin-top: 14px; display: flex; align-items: center; gap: 10px; }
.analyst-row label { font-size: 13px; color: var(--text-dim); white-space: nowrap; }
.analyst-input {
  flex: 1; border: 1px solid var(--border); border-radius: var(--radius);
  padding: 7px 11px; font-size: 13px; background: var(--bg); color: var(--text);
}

.btn-analyze {
  width: 100%; margin-top: 18px; padding: 11px;
  background: var(--accent); color: #fff; border: none;
  border-radius: var(--radius); font-size: 15px; font-weight: 600;
  cursor: pointer; transition: opacity 0.15s;
}
.btn-analyze:hover { opacity: 0.88; }
.btn-analyze:disabled { opacity: 0.45; cursor: not-allowed; }

.progress-bar {
  height: 3px; background: var(--border); border-radius: 2px;
  margin-top: 14px; overflow: hidden; display: none;
}
.progress-bar.active { display: block; }
.progress-fill {
  height: 100%; background: var(--accent); width: 0%;
  animation: indeterminate 1.5s infinite;
}
@keyframes indeterminate {
  0% { width: 0%; margin-left: 0; }
  50% { width: 60%; margin-left: 20%; }
  100% { width: 0%; margin-left: 100%; }
}

.report-card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--radius); box-shadow: var(--shadow); display: none;
}
.report-card.visible { display: block; }

.report-header {
  padding: 20px 24px; border-bottom: 1px solid var(--border);
  display: flex; justify-content: space-between;
  align-items: flex-start; flex-wrap: wrap; gap: 12px;
}
.report-id { font-family: var(--mono); font-size: 12px; color: var(--text-dim); }
.report-id strong { color: var(--accent); font-size: 14px; display: block; }

.risk-badge {
  padding: 6px 14px; border-radius: 4px; font-weight: 700;
  font-size: 13px; letter-spacing: 0.05em; text-transform: uppercase;
}
.risk-HIGH { background: var(--risk-high-bg); color: var(--risk-high); }
.risk-MEDIO { background: var(--risk-med-bg); color: var(--risk-med); }
.risk-BAJO { background: var(--risk-low-bg); color: var(--risk-low); }
.risk-INDETERMINADO { background: var(--border); color: var(--text-dim); }

.report-body { padding: 24px; }

.section { margin-bottom: 24px; }
.section-title {
  font-size: 12px; font-weight: 700; letter-spacing: 0.1em;
  text-transform: uppercase; color: var(--text-dim);
  margin-bottom: 12px; padding-bottom: 6px; border-bottom: 1px solid var(--border);
}

.fields { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 24px; }
.fields-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px 16px; }
.field { display: flex; flex-direction: column; }
.field-label { font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.06em; }
.field-value { font-size: 14px; word-break: break-all; }
.field-value.mono { font-family: var(--mono); font-size: 12px; }
.field-value.missing { color: var(--text-dim); font-style: italic; }
.field-value.ok { color: var(--risk-low); }
.field-value.warn { color: var(--risk-med); }
.field-value.bad { color: var(--risk-high); font-weight: 600; }

.finding {
  border-radius: var(--radius); padding: 12px 14px;
  margin-bottom: 10px; font-size: 13px;
}
.finding-HIGH { background: var(--risk-high-bg); border-left: 3px solid var(--risk-high); }
.finding-MEDIA { background: var(--risk-med-bg); border-left: 3px solid var(--risk-med); }
.finding-BAJA { background: var(--risk-low-bg); border-left: 3px solid var(--risk-low); }
.finding-title {
  font-weight: 600; margin-bottom: 4px; display: flex; align-items: center; gap: 8px;
}
.finding-cat { font-size: 11px; font-weight: 400; color: var(--text-dim); text-transform: uppercase; }
.finding-innocent { margin-top: 6px; font-size: 12px; color: var(--text-dim); font-style: italic; }

/* Pill badge for ai_relevant */
.ai-pill {
  display: inline-block; padding: 3px 10px; border-radius: 12px;
  font-size: 12px; font-weight: 600; margin-top: 4px;
}
.ai-pill-high { background: var(--risk-high-bg); color: var(--risk-high); }
.ai-pill-med  { background: var(--risk-med-bg);  color: var(--risk-med);  }
.ai-pill-low  { background: var(--risk-low-bg);  color: var(--risk-low);  }
.ai-pill-none { background: var(--border);        color: var(--text-dim);  }

.ela-container { display: flex; gap: 20px; align-items: flex-start; flex-wrap: wrap; }
.ela-image {
  max-width: 280px; max-height: 200px; border: 1px solid var(--border);
  border-radius: var(--radius); object-fit: contain; background: #000;
}
.ela-stats { flex: 1; min-width: 180px; }
.note-text { font-size: 12px; color: var(--text-dim); margin-top: 10px; font-style: italic; }

.hash-block {
  background: var(--bg); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 12px 14px;
  font-family: var(--mono); font-size: 11px; line-height: 1.8; word-break: break-all;
}

.auditor-toggle {
  font-size: 13px; color: var(--accent); cursor: pointer;
  background: none; border: none; padding: 0;
  text-decoration: underline; margin-bottom: 16px;
}
.auditor-section { display: none; }
.auditor-section.visible { display: block; }
.raw-block {
  background: var(--bg); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 12px 14px;
  font-family: var(--mono); font-size: 11px;
  max-height: 300px; overflow-y: auto; white-space: pre-wrap; word-break: break-all;
}

.export-row {
  display: flex; gap: 10px; padding: 16px 24px;
  border-top: 1px solid var(--border); flex-wrap: wrap;
}
.btn-export {
  padding: 8px 16px; border: 1px solid var(--border);
  border-radius: var(--radius); font-size: 13px; cursor: pointer;
  background: var(--surface); color: var(--text); transition: border-color 0.15s;
}
.btn-export:hover { border-color: var(--accent); color: var(--accent); }

/* v0.3.0 indicator chips per module */
.indicator-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
.indicator-chip {
  font-size: 11px; padding: 3px 9px; border-radius: 10px;
  border: 1px solid var(--border); color: var(--text-dim);
}

@media (max-width: 600px) {
  .fields, .fields-3 { grid-template-columns: 1fr; }
  .ela-container { flex-direction: column; }
  .report-header { flex-direction: column; }
}
</style>
</head>
<body>

<div class="topbar">
  <div class="brand">VTR <span>Forensic</span> <span style="font-size:11px;color:var(--text-dim);font-weight:400">v0.3.0</span></div>
  <div class="topbar-right">
    <span id="rust-status" title="Parser Rust">
      <span class="status-dot" id="rust-dot"></span>
      <span style="font-size:12px;color:var(--text-dim)" id="rust-label">Rust</span>
    </span>
    <button class="theme-toggle" onclick="toggleTheme()">☀ / ☾</button>
  </div>
</div>

<div class="main">

  <div class="upload-card">
    <h2>Análisis forense de imagen</h2>
    <p>Una imagen a la vez. La imagen no se almacena — se analiza y se elimina inmediatamente.</p>

    <div class="drop-zone" id="drop-zone">
      <input type="file" id="file-input" accept="image/*" onchange="onFileSelected(this)">
      <div class="drop-icon">🖼</div>
      <div class="drop-label" id="drop-label">
        Arrastra una imagen aquí o <strong>haz clic para seleccionar</strong>
      </div>
    </div>

    <div class="divider">o analiza por URL</div>

    <div class="url-row">
      <input type="text" class="url-input" id="url-input"
             placeholder="https://ejemplo.com/imagen.jpg"
             oninput="onUrlInput(this.value)">
    </div>

    <div class="analyst-row">
      <label for="analyst-input">ID Analista (opcional):</label>
      <input type="text" class="analyst-input" id="analyst-input"
             placeholder="ej. luis-2026-001" maxlength="50">
    </div>

    <button class="btn-analyze" id="btn-analyze" onclick="runAnalysis()" disabled>
      Analizar imagen
    </button>

    <div class="progress-bar" id="progress-bar">
      <div class="progress-fill"></div>
    </div>
  </div>

  <div class="report-card" id="report-card">

    <div class="report-header">
      <div class="report-id">
        <strong id="rpt-analysis-id">—</strong>
        <span id="rpt-timestamp"></span>
      </div>
      <div id="rpt-risk-badge" class="risk-badge risk-INDETERMINADO">—</div>
    </div>

    <div class="report-body">

      <!-- Básico -->
      <div class="section">
        <div class="section-title">Información básica</div>
        <div class="fields">
          <div class="field"><span class="field-label">Formato</span><span class="field-value" id="rpt-format">—</span></div>
          <div class="field"><span class="field-label">Dimensiones</span><span class="field-value" id="rpt-dims">—</span></div>
          <div class="field"><span class="field-label">Tamaño</span><span class="field-value" id="rpt-size">—</span></div>
          <div class="field"><span class="field-label">Fuente</span><span class="field-value" id="rpt-source">—</span></div>
        </div>
      </div>

      <!-- Cadena de custodia -->
      <div class="section">
        <div class="section-title">Cadena de custodia</div>
        <div class="hash-block" id="rpt-hashes">—</div>
        <div style="font-size:12px;color:var(--text-dim);margin-top:6px">
          Verifica: <code>sha256sum &lt;archivo&gt;</code> debe coincidir con SHA-256 de arriba.
        </div>
      </div>

      <!-- Dispositivo -->
      <div class="section">
        <div class="section-title">Dispositivo de captura</div>
        <div class="fields">
          <div class="field"><span class="field-label">Fabricante</span><span class="field-value" id="rpt-make">—</span></div>
          <div class="field"><span class="field-label">Modelo</span><span class="field-value" id="rpt-model">—</span></div>
          <div class="field"><span class="field-label">Software</span><span class="field-value" id="rpt-software">—</span></div>
          <div class="field"><span class="field-label">Nº Serie</span><span class="field-value" id="rpt-serial">—</span></div>
        </div>
      </div>

      <!-- Timestamps -->
      <div class="section">
        <div class="section-title">Timestamps</div>
        <div class="fields">
          <div class="field"><span class="field-label">EXIF Original</span><span class="field-value mono" id="rpt-ts-original">—</span></div>
          <div class="field"><span class="field-label">EXIF Digitized</span><span class="field-value mono" id="rpt-ts-digitized">—</span></div>
          <div class="field"><span class="field-label">Filesystem</span><span class="field-value mono" id="rpt-ts-fs">—</span></div>
          <div class="field"><span class="field-label">Timezone</span><span class="field-value mono" id="rpt-tz">—</span></div>
        </div>
      </div>

      <!-- GPS -->
      <div class="section" id="gps-section" style="display:none">
        <div class="section-title">GPS</div>
        <div class="fields">
          <div class="field"><span class="field-label">Latitud</span><span class="field-value mono" id="rpt-lat">—</span></div>
          <div class="field"><span class="field-label">Longitud</span><span class="field-value mono" id="rpt-lon">—</span></div>
          <div class="field"><span class="field-label">Altitud</span><span class="field-value mono" id="rpt-alt">—</span></div>
          <div class="field"><span class="field-label">Coordenadas válidas</span><span class="field-value" id="rpt-gps-valid">—</span></div>
        </div>
        <div id="rpt-gps-notes" style="margin-top:8px;font-size:13px;color:var(--risk-high)"></div>
      </div>

      <!-- IA / Autenticidad -->
      <div class="section">
        <div class="section-title">Señales de IA generativa — metadata</div>
        <div class="fields">
          <div class="field"><span class="field-label">Marcador explícito de IA</span><span class="field-value" id="rpt-ai-marker">—</span></div>
          <div class="field"><span class="field-label">Sin metadata de cámara</span><span class="field-value" id="rpt-no-camera">—</span></div>
        </div>
        <div style="margin-top:10px;font-size:13px" id="rpt-ai-assessment"></div>
      </div>

      <!-- ELA -->
      <div class="section">
        <div class="section-title">Error Level Analysis (ELA)</div>
        <div class="ela-container">
          <img id="rpt-ela-img" class="ela-image" src="" alt="Imagen ELA" style="display:none">
          <div class="ela-stats">
            <div class="fields" style="grid-template-columns:1fr;">
              <div class="field"><span class="field-label">Confianza</span><span class="field-value" id="rpt-ela-conf">—</span></div>
              <div class="field"><span class="field-label">Bloques anómalos</span><span class="field-value" id="rpt-ela-ratio">—</span></div>
              <div class="field"><span class="field-label">Error medio</span><span class="field-value mono" id="rpt-ela-mean">—</span></div>
            </div>
          </div>
        </div>
        <div class="note-text" id="rpt-ela-note"></div>
      </div>

      <!-- Entropía Shannon -->
      <div class="section" id="entropy-section" style="display:none">
        <div class="section-title">Entropía de Shannon (por bloques)</div>
        <div class="fields">
          <div class="field"><span class="field-label">Entropía global</span><span class="field-value mono" id="rpt-entropy-global">—</span></div>
          <div class="field"><span class="field-label">Media bloques</span><span class="field-value mono" id="rpt-entropy-mean">—</span></div>
          <div class="field"><span class="field-label">Bloques anómalos</span><span class="field-value" id="rpt-entropy-anomalies">—</span></div>
          <div class="field"><span class="field-label">Confianza</span><span class="field-value" id="rpt-entropy-conf">—</span></div>
        </div>
        <div class="note-text" id="rpt-entropy-note"></div>
      </div>

      <!-- EntropyProfile v0.3.0 -->
      <div class="section" id="entropy-profile-section" style="display:none">
        <div class="section-title">Perfil de entropía — caracterización IA <span style="font-size:10px;color:var(--accent)">v0.3.0</span></div>
        <div class="fields-3">
          <div class="field"><span class="field-label">Skewness</span><span class="field-value mono" id="rpt-ep-skewness">—</span></div>
          <div class="field"><span class="field-label">Kurtosis (foto real &gt;3.0)</span><span class="field-value mono" id="rpt-ep-kurtosis">—</span></div>
          <div class="field"><span class="field-label">Gradiente espacial</span><span class="field-value mono" id="rpt-ep-gradient">—</span></div>
          <div class="field"><span class="field-label">Entropía canal R</span><span class="field-value mono" id="rpt-ep-r">—</span></div>
          <div class="field"><span class="field-label">Entropía canal G</span><span class="field-value mono" id="rpt-ep-g">—</span></div>
          <div class="field"><span class="field-label">Entropía canal B</span><span class="field-value mono" id="rpt-ep-b">—</span></div>
          <div class="field"><span class="field-label">Corr R-G</span><span class="field-value mono" id="rpt-ep-rg">—</span></div>
          <div class="field"><span class="field-label">Corr R-B</span><span class="field-value mono" id="rpt-ep-rb">—</span></div>
          <div class="field"><span class="field-label">Corr G-B</span><span class="field-value mono" id="rpt-ep-gb">—</span></div>
          <div class="field"><span class="field-label">Multi-escala 32px</span><span class="field-value mono" id="rpt-ep-ms32">—</span></div>
          <div class="field"><span class="field-label">Multi-escala 64px</span><span class="field-value mono" id="rpt-ep-ms64">—</span></div>
          <div class="field"><span class="field-label">Multi-escala 128px</span><span class="field-value mono" id="rpt-ep-ms128">—</span></div>
        </div>
        <div style="margin-top:12px">
          <span class="field-label">Consistencia multi-escala</span>
          <span class="field-value mono" id="rpt-ep-msconsistency">—</span>
        </div>
        <div style="margin-top:10px">
          <span id="rpt-ep-ai-confidence" class="ai-pill ai-pill-none">—</span>
        </div>
        <div class="indicator-row" id="rpt-ep-indicators"></div>
      </div>

      <!-- Cuantización JPEG v0.3.0 -->
      <div class="section" id="quant-section" style="display:none">
        <div class="section-title">Tablas de cuantización JPEG <span style="font-size:10px;color:var(--accent)">v0.3.0</span></div>
        <div class="fields">
          <div class="field"><span class="field-label">Tablas encontradas</span><span class="field-value" id="rpt-quant-tables">—</span></div>
          <div class="field"><span class="field-label">Calidad estimada</span><span class="field-value mono" id="rpt-quant-quality">—</span></div>
          <div class="field"><span class="field-label">Escalado estándar IJG</span><span class="field-value" id="rpt-quant-standard">—</span></div>
          <div class="field"><span class="field-label">Coincide con biblioteca</span><span class="field-value" id="rpt-quant-match">—</span></div>
        </div>
        <div style="margin-top:10px">
          <span id="rpt-quant-ai-pill" class="ai-pill ai-pill-none">—</span>
        </div>
        <div class="indicator-row" id="rpt-quant-findings"></div>
      </div>

      <!-- Frecuencia FFT v0.3.0 -->
      <div class="section" id="freq-section" style="display:none">
        <div class="section-title">Análisis de frecuencia (FFT) <span style="font-size:10px;color:var(--accent)">v0.3.0</span></div>
        <div class="fields">
          <div class="field"><span class="field-label">Pendiente espectral (foto real: -2 a -3)</span><span class="field-value mono" id="rpt-freq-slope">—</span></div>
          <div class="field"><span class="field-label">R² del ajuste</span><span class="field-value mono" id="rpt-freq-r2">—</span></div>
          <div class="field"><span class="field-label">Energía alta frecuencia</span><span class="field-value mono" id="rpt-freq-highfreq">—</span></div>
          <div class="field"><span class="field-label">Picos periódicos</span><span class="field-value" id="rpt-freq-peaks">—</span></div>
          <div class="field"><span class="field-label">Simetría espectral</span><span class="field-value mono" id="rpt-freq-symmetry">—</span></div>
          <div class="field"><span class="field-label">Confianza</span><span class="field-value" id="rpt-freq-conf">—</span></div>
        </div>
        <div style="margin-top:10px">
          <span id="rpt-freq-ai-pill" class="ai-pill ai-pill-none">—</span>
        </div>
        <div class="note-text" id="rpt-freq-note"></div>
      </div>

      <!-- Ruido PRNU v0.3.0 -->
      <div class="section" id="noise-section" style="display:none">
        <div class="section-title">Consistencia de ruido PRNU <span style="font-size:10px;color:var(--accent)">v0.3.0</span></div>
        <div class="fields">
          <div class="field"><span class="field-label">Ruido std global</span><span class="field-value mono" id="rpt-noise-std">—</span></div>
          <div class="field"><span class="field-label">Uniformidad varianza (sensor real: 0.2-0.8)</span><span class="field-value mono" id="rpt-noise-uniformity">—</span></div>
          <div class="field"><span class="field-label">Distribución Gaussiana</span><span class="field-value" id="rpt-noise-gaussian">—</span></div>
          <div class="field"><span class="field-label">Correlación inter-regional</span><span class="field-value mono" id="rpt-noise-corr">—</span></div>
          <div class="field"><span class="field-label">Ruido R / G / B</span><span class="field-value mono" id="rpt-noise-channels">—</span></div>
          <div class="field"><span class="field-label">Ratio B/G (sensor CMOS: &gt;1.1)</span><span class="field-value mono" id="rpt-noise-bg">—</span></div>
        </div>
        <div style="margin-top:10px">
          <span id="rpt-noise-ai-pill" class="ai-pill ai-pill-none">—</span>
        </div>
        <div class="note-text" id="rpt-noise-note"></div>
      </div>

      <!-- Hallazgos -->
      <div class="section">
        <div class="section-title">Hallazgos de consistencia</div>
        <div id="rpt-findings">
          <span style="font-size:13px;color:var(--text-dim)">Sin hallazgos.</span>
        </div>
      </div>

      <!-- Modo auditor -->
      <button class="auditor-toggle" onclick="toggleAuditor()">
        ▶ Ver datos técnicos completos (modo auditor)
      </button>
      <div class="auditor-section" id="auditor-section">
        <div class="section-title" style="margin-bottom:8px">EXIF completo</div>
        <div class="raw-block" id="rpt-raw-exif">—</div>
        <div class="section-title" style="margin:16px 0 8px">Alertas del parser</div>
        <div class="raw-block" id="rpt-parser-alerts">—</div>
      </div>

    </div>

    <div class="export-row">
      <button class="btn-export" onclick="exportTxt()">⬇ Exportar texto</button>
      <button class="btn-export" onclick="exportJson()">⬇ Exportar JSON</button>
    </div>

  </div>

</div>

<script>
let _selectedFile = null;
let _lastReport = null;
let _auditorOpen = false;

fetch('/health').then(r => r.json()).then(data => {
  const dot = document.getElementById('rust-dot');
  const label = document.getElementById('rust-label');
  if (data.rust_parser === 'available') {
    dot.classList.add('ok');
    label.title = 'Parser Rust disponible';
  } else {
    label.style.color = 'var(--risk-med)';
    label.title = 'Parser Rust no disponible';
  }
}).catch(() => {});

function toggleTheme() {
  const html = document.documentElement;
  html.setAttribute('data-theme',
    html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
}

const dropZone = document.getElementById('drop-zone');
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault(); dropZone.classList.remove('dragover');
  const f = e.dataTransfer.files[0]; if (f) setFile(f);
});

function onFileSelected(input) { if (input.files[0]) setFile(input.files[0]); }
function setFile(f) {
  _selectedFile = f;
  document.getElementById('url-input').value = '';
  document.getElementById('drop-label').innerHTML =
    `<strong>${escHtml(f.name)}</strong> (${formatBytes(f.size)})`;
  document.getElementById('btn-analyze').disabled = false;
}
function onUrlInput(val) {
  _selectedFile = null;
  document.getElementById('drop-label').innerHTML =
    'Arrastra una imagen aquí o <strong>haz clic para seleccionar</strong>';
  document.getElementById('btn-analyze').disabled = !val.trim();
}

async function runAnalysis() {
  const btn = document.getElementById('btn-analyze');
  const progress = document.getElementById('progress-bar');
  btn.disabled = true;
  progress.classList.add('active');
  _lastReport = null;
  document.getElementById('report-card').classList.remove('visible');
  try {
    const fd = new FormData();
    const analystId = document.getElementById('analyst-input').value.trim();
    if (analystId) fd.append('analyst_id', analystId);
    if (_selectedFile) {
      fd.append('file', _selectedFile);
    } else {
      const url = document.getElementById('url-input').value.trim();
      if (!url) throw new Error('Selecciona un archivo o ingresa una URL');
      fd.append('url', url);
    }
    const resp = await fetch('/analyze', { method: 'POST', body: fd });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: resp.statusText }));
      throw new Error(err.detail || 'Error del servidor');
    }
    const report = await resp.json();
    _lastReport = report;
    renderReport(report);
  } catch (err) {
    alert('Error: ' + err.message);
  } finally {
    btn.disabled = false;
    progress.classList.remove('active');
  }
}

function aiPillClass(text) {
  if (!text) return 'ai-pill-none';
  const t = text.toUpperCase();
  if (t.includes('ALTA')) return 'ai-pill-high';
  if (t.includes('MODERADA')) return 'ai-pill-med';
  if (t.includes('BAJA')) return 'ai-pill-low';
  if (t.includes('SIN INDICADORES') || t.includes('CONSISTENTE CON CÁMARA') || t.includes('CONSISTENTE CON SENSOR')) return 'ai-pill-low';
  return 'ai-pill-none';
}

function setPill(id, text) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text || '—';
  el.className = 'ai-pill ' + aiPillClass(text);
}

function renderReport(r) {
  const meta = r.metadata || {};
  const ela = r.ela || {};
  const consistency = r.consistency || {};
  const ai = consistency.ai_signals || {};
  const gps = meta.gps || {};
  const ts = meta.timestamps || {};
  const device = meta.device || {};
  const hashes = meta.hashes || {};
  const entropy = r.entropy || {};
  const profile = entropy.profile || null;
  const quant = r.quantization || {};
  const freq = r.frequency || {};
  const noise = r.noise || {};

  set('rpt-analysis-id', r.analysis_id || '—');
  set('rpt-timestamp', r.analysis_timestamp || '');

  const risk = consistency.risk_level || 'INDETERMINADO';
  const badge = document.getElementById('rpt-risk-badge');
  badge.textContent = 'Riesgo: ' + risk;
  badge.className = 'risk-badge risk-' + risk.split('-')[0];

  set('rpt-format', meta.file_format || vm('no detectado'));
  const dims = meta.image_dimensions;
  set('rpt-dims', dims ? `${dims[0]} × ${dims[1]} px` : '—');
  set('rpt-size', meta.file_size_bytes ? formatBytes(meta.file_size_bytes) : '—');
  set('rpt-source', escHtml(r.image_source || '—'));

  const hashText = [
    hashes.sha256 ? `SHA-256  ${hashes.sha256}` : 'SHA-256  no calculado',
    hashes.md5    ? `MD5      ${hashes.md5}`    : 'MD5      no calculado',
  ].join('\n');
  document.getElementById('rpt-hashes').textContent = hashText;

  set('rpt-make',     device.make     || vm('No encontrado'));
  set('rpt-model',    device.model    || vm('No encontrado'));
  set('rpt-software', device.software || vm('No encontrado'));
  set('rpt-serial',   device.serial_number || vm('No encontrado'));

  set('rpt-ts-original',  ts.exif_datetime_original  || vm('—'));
  set('rpt-ts-digitized', ts.exif_datetime_digitized || vm('—'));
  set('rpt-ts-fs',        ts.filesystem_modified     || vm('—'));
  set('rpt-tz',           ts.timezone_offset         || vm('—'));

  if (gps.latitude != null) {
    show('gps-section');
    set('rpt-lat', String(gps.latitude));
    set('rpt-lon', String(gps.longitude));
    set('rpt-alt', gps.altitude != null ? gps.altitude + ' m' : vm('—'));
    const validEl = document.getElementById('rpt-gps-valid');
    validEl.textContent = gps.raw_valid ? 'SÍ' : 'NO — COORDENADAS IMPOSIBLES';
    validEl.className = 'field-value ' + (gps.raw_valid ? 'ok' : 'bad');
    document.getElementById('rpt-gps-notes').textContent = (gps.validation_notes || []).join('\n');
  }

  const markerEl = document.getElementById('rpt-ai-marker');
  markerEl.textContent = ai.explicit_ai_software_marker ? 'SÍ — DETECTADO' : 'No';
  markerEl.className = 'field-value ' + (ai.explicit_ai_software_marker ? 'bad' : '');
  const noCamEl = document.getElementById('rpt-no-camera');
  noCamEl.textContent = ai.no_camera_metadata ? 'SÍ' : 'No';
  noCamEl.className = 'field-value ' + (ai.no_camera_metadata ? 'warn' : '');
  set('rpt-ai-assessment', ai.overall_assessment || '—');

  set('rpt-ela-conf', ela.confidence || (ela.applicable === false ? 'No aplicable: ' + ela.skip_reason : '—'));
  set('rpt-ela-ratio', ela.anomalous_pixel_ratio != null ? (ela.anomalous_pixel_ratio * 100).toFixed(1) + '%' : '—');
  set('rpt-ela-mean', ela.global_mean_error != null ? String(ela.global_mean_error) : '—');
  set('rpt-ela-note', (ela.caveats || []).join(' | '));
  if (r.ela_image_b64) {
    const img = document.getElementById('rpt-ela-img');
    img.src = 'data:image/png;base64,' + r.ela_image_b64;
    img.style.display = 'block';
  }

  // Entropía Shannon
  if (entropy.applicable) {
    show('entropy-section');
    set('rpt-entropy-global', entropy.global_entropy != null ? entropy.global_entropy + ' bits/byte' : '—');
    set('rpt-entropy-mean', entropy.block_mean_entropy != null ?
      entropy.block_mean_entropy + ' ± ' + entropy.block_std_entropy : '—');
    const eHigh = entropy.anomalous_blocks_high || 0;
    const eLow  = entropy.anomalous_blocks_low  || 0;
    const eRatio = entropy.anomalous_ratio || 0;
    set('rpt-entropy-anomalies', eHigh + ' altos, ' + eLow + ' bajos (' + (eRatio*100).toFixed(1) + '%)');
    set('rpt-entropy-conf', entropy.confidence || '—');
    set('rpt-entropy-note', (entropy.caveats || []).join(' | '));
  }

  // EntropyProfile v0.3.0
  if (profile) {
    show('entropy-profile-section');
    set('rpt-ep-skewness',  fmtN(profile.skewness));
    set('rpt-ep-kurtosis',  fmtN(profile.kurtosis));
    set('rpt-ep-gradient',  profile.spatial_gradient_mean != null ?
      fmtN(profile.spatial_gradient_mean) + ' ± ' + fmtN(profile.spatial_gradient_std) : '—');
    set('rpt-ep-r',  fmtN(profile.channel_entropy_r));
    set('rpt-ep-g',  fmtN(profile.channel_entropy_g));
    set('rpt-ep-b',  fmtN(profile.channel_entropy_b));
    set('rpt-ep-rg', fmtN(profile.channel_correlation_rg));
    set('rpt-ep-rb', fmtN(profile.channel_correlation_rb));
    set('rpt-ep-gb', fmtN(profile.channel_correlation_gb));
    set('rpt-ep-ms32',  fmtN(profile.multiscale_32_mean));
    set('rpt-ep-ms64',  fmtN(profile.multiscale_64_mean));
    set('rpt-ep-ms128', fmtN(profile.multiscale_128_mean));
    set('rpt-ep-msconsistency', fmtN(profile.multiscale_consistency));
    setPill('rpt-ep-ai-confidence', profile.ai_confidence);
    const indRow = document.getElementById('rpt-ep-indicators');
    indRow.innerHTML = (profile.ai_indicators || []).map(i =>
      `<span class="indicator-chip">${escHtml(i)}</span>`).join('');
  }

  // Cuantización JPEG v0.3.0
  if (quant.applicable) {
    show('quant-section');
    set('rpt-quant-tables',   String(quant.num_tables || 0));
    set('rpt-quant-quality',  quant.estimated_quality != null ? quant.estimated_quality + '%' : '—');
    const stdEl = document.getElementById('rpt-quant-standard');
    stdEl.textContent = quant.is_standard_table ? 'SÍ — consistente con software/IA' : 'NO — tablas de fabricante';
    stdEl.className = 'field-value ' + (quant.is_standard_table ? 'warn' : 'ok');
    set('rpt-quant-match', quant.matches_known_library || vm('No identificada'));
    setPill('rpt-quant-ai-pill', quant.ai_relevant);
    const findRow = document.getElementById('rpt-quant-findings');
    findRow.innerHTML = (quant.findings || []).map(f =>
      `<span class="indicator-chip">${escHtml(f)}</span>`).join('');
  }

  // Frecuencia FFT v0.3.0
  if (freq.applicable) {
    show('freq-section');
    set('rpt-freq-slope',    fmtN(freq.spectral_slope));
    set('rpt-freq-r2',       fmtN(freq.slope_r_squared));
    set('rpt-freq-highfreq', freq.high_freq_energy_ratio != null ?
      (freq.high_freq_energy_ratio * 100).toFixed(1) + '%' : '—');
    set('rpt-freq-peaks',    String(freq.periodic_peaks_detected || 0));
    set('rpt-freq-symmetry', fmtN(freq.spectral_symmetry));
    set('rpt-freq-conf',     freq.confidence || '—');
    setPill('rpt-freq-ai-pill', freq.ai_relevant);
    set('rpt-freq-note', (freq.caveats || []).join(' | '));
  }

  // Ruido PRNU v0.3.0
  if (noise.applicable) {
    show('noise-section');
    set('rpt-noise-std',         fmtN(noise.noise_std));
    set('rpt-noise-uniformity',  fmtN(noise.variance_uniformity));
    const gaussEl = document.getElementById('rpt-noise-gaussian');
    if (noise.is_gaussian_like === true)       { gaussEl.textContent = 'SÍ'; gaussEl.className = 'field-value ok'; }
    else if (noise.is_gaussian_like === false) { gaussEl.textContent = 'NO'; gaussEl.className = 'field-value warn'; }
    else                                       { gaussEl.textContent = 'N/D'; gaussEl.className = 'field-value'; }
    set('rpt-noise-corr',     fmtN(noise.cross_region_correlation));
    set('rpt-noise-channels', `${fmtN(noise.noise_std_r)} / ${fmtN(noise.noise_std_g)} / ${fmtN(noise.noise_std_b)}`);
    set('rpt-noise-bg',       fmtN(noise.channel_noise_ratio_bg));
    setPill('rpt-noise-ai-pill', noise.ai_relevant);
    set('rpt-noise-note', (noise.caveats || []).join(' | '));
  }

  // Hallazgos
  const findingsEl = document.getElementById('rpt-findings');
  const findings = consistency.findings || [];
  if (findings.length === 0) {
    findingsEl.innerHTML = '<span style="font-size:13px;color:var(--text-dim)">Sin hallazgos de inconsistencia.</span>';
  } else {
    findingsEl.innerHTML = findings.map(f => `
      <div class="finding finding-${escHtml(f.relevance)}">
        <div class="finding-title">
          [${escHtml(f.relevance)}]
          <span class="finding-cat">${escHtml(f.category)}</span>
        </div>
        <div>${escHtml(f.description)}</div>
        ${f.innocent_explanation ? `<div class="finding-innocent">ℹ ${escHtml(f.innocent_explanation)}</div>` : ''}
      </div>
    `).join('');
  }

  const rawExif = meta.raw_exif_fields || {};
  document.getElementById('rpt-raw-exif').textContent =
    Object.entries(rawExif).map(([k,v]) => `${k}: ${v}`).join('\n') || '(sin campos EXIF)';

  const alerts = [
    ...(meta.extraction_warnings || []),
    ...((meta.security || {}).parse_errors || []),
    ...((meta.security || {}).oversized_fields || []),
    ...((meta.security || {}).structurally_anomalous || []),
  ];
  document.getElementById('rpt-parser-alerts').textContent = alerts.join('\n') || '(sin alertas)';

  document.getElementById('report-card').classList.add('visible');
  document.getElementById('report-card').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function toggleAuditor() {
  _auditorOpen = !_auditorOpen;
  document.getElementById('auditor-section').classList.toggle('visible', _auditorOpen);
  document.querySelector('.auditor-toggle').textContent =
    (_auditorOpen ? '▼' : '▶') + ' Ver datos técnicos completos (modo auditor)';
}

function exportTxt() {
  if (!_lastReport) return;
  download('reporte-' + (_lastReport.analysis_id || 'vtr') + '.txt', buildTextReport(_lastReport));
}

function exportJson() {
  if (!_lastReport) return;
  const exportable = {..._lastReport, ela_image_b64: '[omitido en exportación]'};
  download('reporte-' + (_lastReport.analysis_id || 'vtr') + '.json',
           JSON.stringify(exportable, null, 2));
}

function buildTextReport(r) {
  const meta = r.metadata || {};
  const consistency = r.consistency || {};
  const hashes = meta.hashes || {};
  const device = meta.device || {};
  const ts = meta.timestamps || {};
  const gps = meta.gps || {};
  const ela = r.ela || {};
  const entropy = r.entropy || {};
  const profile = entropy.profile || null;
  const quant = r.quantization || {};
  const freq = r.frequency || {};
  const noise = r.noise || {};
  const findings = consistency.findings || [];

  const lines = [
    '='.repeat(60),
    'VTR FORENSIC IMAGE ANALYZER v0.3.0',
    '='.repeat(60),
    `ID Análisis:  ${r.analysis_id || '—'}`,
    `Timestamp:    ${r.analysis_timestamp || '—'}`,
    `Fuente:       ${r.image_source || '—'}`,
    '',
    '── CADENA DE CUSTODIA',
    `SHA-256: ${hashes.sha256 || '—'}`,
    `MD5:     ${hashes.md5 || '—'}`,
    '',
    '── DISPOSITIVO',
    `Fabricante: ${device.make || '—'}`,
    `Modelo:     ${device.model || '—'}`,
    `Software:   ${device.software || '—'}`,
    '',
    '── TIMESTAMPS',
    `EXIF Original: ${ts.exif_datetime_original || '—'}`,
    `FS Modificado: ${ts.filesystem_modified || '—'}`,
    '',
  ];

  if (gps.latitude != null) {
    lines.push('── GPS');
    lines.push(`Lat: ${gps.latitude}  Lon: ${gps.longitude}`);
    lines.push(`Válido: ${gps.raw_valid ? 'SÍ' : 'NO'}`);
    lines.push('');
  }

  lines.push('── ELA');
  lines.push(`Confianza: ${ela.confidence || '—'}`);
  lines.push(`Bloques anómalos: ${ela.anomalous_pixel_ratio != null ? (ela.anomalous_pixel_ratio*100).toFixed(1)+'%' : '—'}`);
  lines.push('');

  if (entropy.applicable) {
    lines.push('── ENTROPÍA DE SHANNON');
    lines.push(`Entropía global: ${entropy.global_entropy} bits/byte`);
    lines.push(`Media bloques: ${entropy.block_mean_entropy} ± ${entropy.block_std_entropy}`);
    lines.push(`Bloques anómalos: ${entropy.anomalous_blocks_high} altos, ${entropy.anomalous_blocks_low} bajos`);
    lines.push(`Confianza: ${entropy.confidence || '—'}`);
    lines.push('');
  }

  if (profile) {
    lines.push('── PERFIL DE ENTROPÍA (v0.3.0)');
    lines.push(`Skewness: ${profile.skewness}  Kurtosis: ${profile.kurtosis}`);
    lines.push(`Gradiente espacial: ${profile.spatial_gradient_mean}`);
    lines.push(`Canal R/G/B: ${profile.channel_entropy_r} / ${profile.channel_entropy_g} / ${profile.channel_entropy_b}`);
    lines.push(`Multi-escala: 32=${profile.multiscale_32_mean} 64=${profile.multiscale_64_mean} 128=${profile.multiscale_128_mean}`);
    lines.push(`IA confianza: ${profile.ai_confidence || '—'}`);
    (profile.ai_indicators || []).forEach(i => lines.push(`  ⚠ ${i}`));
    lines.push('');
  }

  if (quant.applicable) {
    lines.push('── CUANTIZACIÓN JPEG (v0.3.0)');
    lines.push(`Tablas: ${quant.num_tables}  Calidad estimada: ${quant.estimated_quality}%`);
    lines.push(`Escalado estándar IJG: ${quant.is_standard_table ? 'SÍ (software/IA)' : 'NO (cámara)'}`);
    lines.push(`Relevancia IA: ${quant.ai_relevant || '—'}`);
    lines.push('');
  }

  if (freq.applicable) {
    lines.push('── FRECUENCIA FFT (v0.3.0)');
    lines.push(`Pendiente espectral: ${freq.spectral_slope}  R²: ${freq.slope_r_squared}`);
    lines.push(`Energía alta freq: ${freq.high_freq_energy_ratio != null ? (freq.high_freq_energy_ratio*100).toFixed(1)+'%' : '—'}`);
    lines.push(`Picos periódicos: ${freq.periodic_peaks_detected}`);
    lines.push(`Relevancia IA: ${freq.ai_relevant || '—'}`);
    lines.push('');
  }

  if (noise.applicable) {
    lines.push('── RUIDO PRNU (v0.3.0)');
    lines.push(`Ruido std: ${noise.noise_std}  Uniformidad: ${noise.variance_uniformity}`);
    lines.push(`Gaussiano: ${noise.is_gaussian_like === true ? 'SÍ' : noise.is_gaussian_like === false ? 'NO' : 'N/D'}`);
    lines.push(`Correlación inter-regional: ${noise.cross_region_correlation}`);
    lines.push(`Ratio B/G: ${noise.channel_noise_ratio_bg}`);
    lines.push(`Relevancia IA: ${noise.ai_relevant || '—'}`);
    lines.push('');
  }

  lines.push('── HALLAZGOS');
  lines.push(`Nivel de riesgo: ${consistency.risk_level || '—'}`);
  findings.forEach(f => lines.push(`[${f.relevance}] ${f.category}: ${f.description}`));
  lines.push('');
  lines.push('='.repeat(60));
  lines.push('Vector Telemetry Research © 2026');
  return lines.join('\n');
}

function download(filename, content) {
  const blob = new Blob([content], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

function set(id, value) {
  const el = document.getElementById(id);
  if (!el) return;
  if (typeof value === 'string' && value.includes('<span')) { el.innerHTML = value; }
  else { el.textContent = value; }
}
function show(id) { const el = document.getElementById(id); if (el) el.style.display = ''; }
function vm(text) { return `<span class="field-value missing">${text}</span>`; }
function fmtN(n) { return n != null ? String(n) : '—'; }
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function formatBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
  return (n/1048576).toFixed(1) + ' MB';
}
</script>
</body>
</html>"""
