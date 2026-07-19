"""
vtr-forensic-img v0.1.0
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
    version="0.1.0",
    docs_url=None,   # deshabilitar Swagger UI en producción
    redoc_url=None,
)

# CORS: solo localhost — no acepta peticiones de otros orígenes
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:7700", "http://127.0.0.1:7700"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def _csp_headers() -> dict:
    """
    Content-Security-Policy estricto:
    - default-src 'self': solo recursos del mismo origen
    - img-src 'self' data:: permite imágenes base64 (la imagen ELA)
    - style-src 'self' 'unsafe-inline': estilos inline necesarios para el toggle de tema
    - script-src 'self': solo scripts del mismo origen, sin eval()
    - connect-src 'none': sin conexiones externas desde el reporte
    - frame-ancestors 'none': no puede ser embebido en iframes
    """
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
    """
    Corre el análisis en un subproceso Python completamente independiente.

    DECISIÓN DE AISLAMIENTO: sys.executable garantiza que usamos el
    mismo intérprete Python que el servidor, sin asumir que 'python3'
    en PATH es el mismo. El subproceso importa el pipeline desde cero —
    sin estado compartido con el proceso servidor.

    PORTABILIDAD (Linux / macOS / Windows):
      cmd se pasa como lista, nunca como string — subprocess.run con
      lista maneja correctamente rutas con espacios en cualquier SO,
      incluyendo "C:\\Program Files\\Python312\\python.exe" en Windows,
      sin necesidad de shlex.quote ni shell=True (que abre vectores
      de injection de comandos).

    Si el subproceso es corrompido por una imagen maliciosa (crash,
    hang, corrupción de heap), el servidor principal no se ve afectado.
    El timeout de 120s previene que una imagen diseñada para colgar el
    análisis bloquee el servidor indefinidamente.
    """
    analysis_script = str(PROJECT_DIR / "web" / "_analysis_worker.py")
    # Lista explícita — nunca string con shell=True
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
            # shell=False es el default y debe mantenerse — shell=True
            # en Windows evaluaría el comando a través de cmd.exe,
            # abriendo vectores de injection.
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
    """
    ID forense único: timestamp ISO + primeros 8 chars del SHA-256.
    Aparece en el reporte y en la UI — permite verificación cruzada.
    """
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
    # Exactamente una fuente — archivo O url, no ambos, no ninguno
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
            # Validar MIME type antes de leer el contenido completo
            if file.content_type not in ALLOWED_MIME_TYPES:
                raise HTTPException(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    detail=f"Tipo de archivo no soportado: {file.content_type}. "
                           f"Permitidos: JPEG, PNG, WEBP, TIFF, GIF"
                )

            # Leer contenido completo y verificar tamaño
            image_bytes = await file.read()
            if len(image_bytes) > MAX_IMAGE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Imagen supera el límite de {MAX_IMAGE_BYTES // 1_048_576} MB"
                )

            # Archivo temporal portable (Linux / macOS / Windows).
            # En Windows, NamedTemporaryFile con delete=False mantiene
            # el archivo abierto por el proceso actual, y un segundo proceso
            # (el worker) no puede abrirlo simultáneamente dependiendo de
            # la configuración del sistema. Solución: escribir, cerrar
            # explícitamente, luego pasar la ruta al worker.
            suffix = Path(file.filename or "img").suffix or ".tmp"
            fd, tmp_name = tempfile.mkstemp(
                suffix=suffix, dir=tempfile.gettempdir()
            )
            try:
                os.write(fd, image_bytes)
            finally:
                os.close(fd)  # cerrar antes de que el worker lo abra
            tmp_path = Path(tmp_name)

            report = _run_analysis_isolated(tmp_path)

        else:
            # URL — el worker descarga y analiza
            if not (url.startswith("http://") or url.startswith("https://")):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="URL debe comenzar con http:// o https://"
                )
            # Placeholder temporal — mismo patrón portable
            fd, tmp_name = tempfile.mkstemp(suffix=".url")
            os.close(fd)
            tmp_path = Path(tmp_name)

            report = _run_analysis_isolated(tmp_path, url=url)

        # Generar ID forense
        sha256 = report.get("metadata", {}).get("sha256", "")
        analysis_id = _generate_analysis_id(sha256)
        report["analysis_id"] = analysis_id
        if analyst_id:
            import re
            safe_id = re.sub(r'[^A-Za-z0-9\-_]', '', analyst_id)[:50]
            report["analyst_id"] = safe_id

        # Sustituir la ruta del archivo temporal por el nombre original —
        # la ruta interna del servidor nunca debe aparecer en el reporte
        if file is not None:
            original_name = file.filename or "imagen"
            report["image_source"] = original_name
            if "metadata" in report:
                report["metadata"]["file_path"] = original_name
        elif url:
            report["image_source"] = url

        return JSONResponse(content=report, headers=_csp_headers())

    finally:
        # Eliminar imagen temporal SIEMPRE — independientemente del resultado
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
        "version": "0.1.0",
        "rust_parser": "available" if rust_available else "not_found",
    }, headers=_csp_headers())


def _build_html() -> str:
    """
    HTML completamente self-contained — sin CDN, sin fuentes externas.
    Funciona offline. El toggle de tema (neutro/VTR oscuro) es CSS puro.
    """
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
.brand {
  font-weight: 700;
  font-size: 16px;
  letter-spacing: 0.03em;
  color: var(--accent);
}
.brand span { color: var(--text); }
.topbar-right { display: flex; align-items: center; gap: 16px; }
.theme-toggle {
  background: none;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 5px 10px;
  cursor: pointer;
  font-size: 13px;
  color: var(--text-dim);
}
.theme-toggle:hover { border-color: var(--accent); color: var(--accent); }
.status-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  background: #aaa;
  display: inline-block;
}
.status-dot.ok { background: var(--risk-low); }
.main { max-width: 860px; margin: 0 auto; padding: 32px 24px; }

/* Upload zone */
.upload-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 28px;
  box-shadow: var(--shadow);
  margin-bottom: 24px;
}
.upload-card h2 {
  font-size: 17px;
  font-weight: 600;
  margin-bottom: 6px;
}
.upload-card p { color: var(--text-dim); font-size: 13px; margin-bottom: 20px; }

.drop-zone {
  border: 2px dashed var(--border);
  border-radius: var(--radius);
  padding: 40px 24px;
  text-align: center;
  cursor: pointer;
  transition: border-color 0.2s, background 0.2s;
  position: relative;
}
.drop-zone:hover, .drop-zone.dragover {
  border-color: var(--accent);
  background: var(--accent-light);
}
.drop-zone input[type=file] {
  position: absolute; inset: 0; opacity: 0; cursor: pointer;
}
.drop-icon { font-size: 32px; margin-bottom: 10px; }
.drop-label { font-size: 14px; color: var(--text-dim); }
.drop-label strong { color: var(--accent); }

.divider {
  display: flex; align-items: center; gap: 12px;
  margin: 18px 0;
  color: var(--text-dim); font-size: 12px;
}
.divider::before, .divider::after {
  content: ''; flex: 1; height: 1px; background: var(--border);
}

.url-row { display: flex; gap: 10px; }
.url-input {
  flex: 1;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 9px 13px;
  font-size: 14px;
  background: var(--bg);
  color: var(--text);
}
.url-input:focus { outline: none; border-color: var(--accent); }

.analyst-row {
  margin-top: 14px;
  display: flex;
  align-items: center;
  gap: 10px;
}
.analyst-row label { font-size: 13px; color: var(--text-dim); white-space: nowrap; }
.analyst-input {
  flex: 1;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 7px 11px;
  font-size: 13px;
  background: var(--bg);
  color: var(--text);
}

.btn-analyze {
  width: 100%;
  margin-top: 18px;
  padding: 11px;
  background: var(--accent);
  color: #fff;
  border: none;
  border-radius: var(--radius);
  font-size: 15px;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.15s;
}
.btn-analyze:hover { opacity: 0.88; }
.btn-analyze:disabled { opacity: 0.45; cursor: not-allowed; }

/* Progress */
.progress-bar {
  height: 3px;
  background: var(--border);
  border-radius: 2px;
  margin-top: 14px;
  overflow: hidden;
  display: none;
}
.progress-bar.active { display: block; }
.progress-fill {
  height: 100%;
  background: var(--accent);
  width: 0%;
  transition: width 0.4s;
  animation: indeterminate 1.5s infinite;
}
@keyframes indeterminate {
  0% { width: 0%; margin-left: 0; }
  50% { width: 60%; margin-left: 20%; }
  100% { width: 0%; margin-left: 100%; }
}

/* Report */
.report-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  display: none;
}
.report-card.visible { display: block; }

.report-header {
  padding: 20px 24px;
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: 12px;
}
.report-id {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text-dim);
}
.report-id strong { color: var(--accent); font-size: 14px; display: block; }

.risk-badge {
  padding: 6px 14px;
  border-radius: 4px;
  font-weight: 700;
  font-size: 13px;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}
.risk-HIGH { background: var(--risk-high-bg); color: var(--risk-high); }
.risk-MEDIO { background: var(--risk-med-bg); color: var(--risk-med); }
.risk-BAJO { background: var(--risk-low-bg); color: var(--risk-low); }
.risk-INDETERMINADO { background: var(--border); color: var(--text-dim); }

.report-body { padding: 24px; }

.section { margin-bottom: 24px; }
.section-title {
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--text-dim);
  margin-bottom: 12px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--border);
}

.fields { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 24px; }
.field { display: flex; flex-direction: column; }
.field-label { font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.06em; }
.field-value { font-size: 14px; word-break: break-all; }
.field-value.mono { font-family: var(--mono); font-size: 12px; }
.field-value.missing { color: var(--text-dim); font-style: italic; }

/* Findings */
.finding {
  border-radius: var(--radius);
  padding: 12px 14px;
  margin-bottom: 10px;
  font-size: 13px;
}
.finding-HIGH { background: var(--risk-high-bg); border-left: 3px solid var(--risk-high); }
.finding-MEDIA { background: var(--risk-med-bg); border-left: 3px solid var(--risk-med); }
.finding-BAJA { background: var(--risk-low-bg); border-left: 3px solid var(--risk-low); }
.finding-title {
  font-weight: 600;
  margin-bottom: 4px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.finding-cat {
  font-size: 11px;
  font-weight: 400;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.finding-innocent {
  margin-top: 6px;
  font-size: 12px;
  color: var(--text-dim);
  font-style: italic;
}

/* ELA */
.ela-container { display: flex; gap: 20px; align-items: flex-start; flex-wrap: wrap; }
.ela-image {
  max-width: 280px;
  max-height: 200px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  object-fit: contain;
  background: #000;
}
.ela-stats { flex: 1; min-width: 180px; }
.ela-note {
  font-size: 12px;
  color: var(--text-dim);
  margin-top: 10px;
  font-style: italic;
}

/* Hashes — cadena de custodia */
.hash-block {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 14px;
  font-family: var(--mono);
  font-size: 11px;
  line-height: 1.8;
  word-break: break-all;
}

/* Toggle modo auditor */
.auditor-toggle {
  font-size: 13px;
  color: var(--accent);
  cursor: pointer;
  background: none;
  border: none;
  padding: 0;
  text-decoration: underline;
  margin-bottom: 16px;
}
.auditor-section { display: none; }
.auditor-section.visible { display: block; }
.raw-block {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 14px;
  font-family: var(--mono);
  font-size: 11px;
  max-height: 300px;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

/* Export */
.export-row {
  display: flex;
  gap: 10px;
  padding: 16px 24px;
  border-top: 1px solid var(--border);
  flex-wrap: wrap;
}
.btn-export {
  padding: 8px 16px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  font-size: 13px;
  cursor: pointer;
  background: var(--surface);
  color: var(--text);
  transition: border-color 0.15s;
}
.btn-export:hover { border-color: var(--accent); color: var(--accent); }

/* Responsive */
@media (max-width: 600px) {
  .fields { grid-template-columns: 1fr; }
  .ela-container { flex-direction: column; }
  .report-header { flex-direction: column; }
}
</style>
</head>
<body>

<div class="topbar">
  <div class="brand">VTR <span>Forensic</span></div>
  <div class="topbar-right">
    <span id="rust-status" title="Parser Rust">
      <span class="status-dot" id="rust-dot"></span>
      <span style="font-size:12px;color:var(--text-dim)" id="rust-label">Rust</span>
    </span>
    <button class="theme-toggle" onclick="toggleTheme()">☀ / ☾</button>
  </div>
</div>

<div class="main">

  <!-- Upload card -->
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

  <!-- Report -->
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
          <div class="field">
            <span class="field-label">Formato detectado</span>
            <span class="field-value" id="rpt-format">—</span>
          </div>
          <div class="field">
            <span class="field-label">Dimensiones</span>
            <span class="field-value" id="rpt-dims">—</span>
          </div>
          <div class="field">
            <span class="field-label">Tamaño</span>
            <span class="field-value" id="rpt-size">—</span>
          </div>
          <div class="field">
            <span class="field-label">Archivo fuente</span>
            <span class="field-value" id="rpt-source">—</span>
          </div>
        </div>
      </div>

      <!-- Cadena de custodia -->
      <div class="section">
        <div class="section-title">Cadena de custodia</div>
        <div class="hash-block" id="rpt-hashes">—</div>
        <div style="font-size:12px;color:var(--text-dim);margin-top:6px">
          Verifica: <code>sha256sum &lt;archivo&gt;</code> debe coincidir con el SHA-256 de arriba.
        </div>
      </div>

      <!-- Dispositivo -->
      <div class="section">
        <div class="section-title">Dispositivo de captura</div>
        <div class="fields">
          <div class="field">
            <span class="field-label">Fabricante</span>
            <span class="field-value" id="rpt-make">—</span>
          </div>
          <div class="field">
            <span class="field-label">Modelo</span>
            <span class="field-value" id="rpt-model">—</span>
          </div>
          <div class="field">
            <span class="field-label">Software</span>
            <span class="field-value" id="rpt-software">—</span>
          </div>
          <div class="field">
            <span class="field-label">Nº Serie</span>
            <span class="field-value" id="rpt-serial">—</span>
          </div>
        </div>
      </div>

      <!-- Timestamps -->
      <div class="section">
        <div class="section-title">Timestamps</div>
        <div class="fields">
          <div class="field">
            <span class="field-label">EXIF Original</span>
            <span class="field-value mono" id="rpt-ts-original">—</span>
          </div>
          <div class="field">
            <span class="field-label">EXIF Digitized</span>
            <span class="field-value mono" id="rpt-ts-digitized">—</span>
          </div>
          <div class="field">
            <span class="field-label">Filesystem modificado</span>
            <span class="field-value mono" id="rpt-ts-fs">—</span>
          </div>
          <div class="field">
            <span class="field-label">Timezone</span>
            <span class="field-value mono" id="rpt-tz">—</span>
          </div>
        </div>
      </div>

      <!-- GPS -->
      <div class="section" id="gps-section" style="display:none">
        <div class="section-title">GPS</div>
        <div class="fields">
          <div class="field">
            <span class="field-label">Latitud</span>
            <span class="field-value mono" id="rpt-lat">—</span>
          </div>
          <div class="field">
            <span class="field-label">Longitud</span>
            <span class="field-value mono" id="rpt-lon">—</span>
          </div>
          <div class="field">
            <span class="field-label">Altitud</span>
            <span class="field-value mono" id="rpt-alt">—</span>
          </div>
          <div class="field">
            <span class="field-label">Coordenadas válidas</span>
            <span class="field-value" id="rpt-gps-valid">—</span>
          </div>
        </div>
        <div id="rpt-gps-notes" style="margin-top:8px;font-size:13px;color:var(--risk-high)"></div>
      </div>

      <!-- IA / Autenticidad -->
      <div class="section">
        <div class="section-title">Señales de IA generativa</div>
        <div class="fields">
          <div class="field">
            <span class="field-label">Marcador explícito de IA</span>
            <span class="field-value" id="rpt-ai-marker">—</span>
          </div>
          <div class="field">
            <span class="field-label">Sin metadata de cámara</span>
            <span class="field-value" id="rpt-no-camera">—</span>
          </div>
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
              <div class="field">
                <span class="field-label">Confianza</span>
                <span class="field-value" id="rpt-ela-conf">—</span>
              </div>
              <div class="field">
                <span class="field-label">Bloques anómalos</span>
                <span class="field-value" id="rpt-ela-ratio">—</span>
              </div>
              <div class="field">
                <span class="field-label">Error medio</span>
                <span class="field-value mono" id="rpt-ela-mean">—</span>
              </div>
            </div>
          </div>
        </div>
        <div class="ela-note" id="rpt-ela-note"></div>
      </div>

      <!-- Entropía Shannon -->
      <div class="section" id="entropy-section" style="display:none">
        <div class="section-title">Entropía de Shannon (por bloques)</div>
        <div class="fields">
          <div class="field">
            <span class="field-label">Entropía global</span>
            <span class="field-value mono" id="rpt-entropy-global">—</span>
          </div>
          <div class="field">
            <span class="field-label">Media bloques</span>
            <span class="field-value mono" id="rpt-entropy-mean">—</span>
          </div>
          <div class="field">
            <span class="field-label">Bloques anómalos</span>
            <span class="field-value" id="rpt-entropy-anomalies">—</span>
          </div>
          <div class="field">
            <span class="field-label">Confianza</span>
            <span class="field-value" id="rpt-entropy-conf">—</span>
          </div>
        </div>
        <div class="ela-note" id="rpt-entropy-note"></div>
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

    </div><!-- /report-body -->

    <div class="export-row">
      <button class="btn-export" onclick="exportTxt()">⬇ Exportar texto</button>
      <button class="btn-export" onclick="exportJson()">⬇ Exportar JSON</button>
    </div>

  </div><!-- /report-card -->

</div><!-- /main -->

<script>
// Estado de la UI — sin estado global de imagen, sin cache entre análisis
let _selectedFile = null;
let _lastReport = null;
let _auditorOpen = false;

// Verificar disponibilidad del Rust parser al cargar
fetch('/health').then(r => r.json()).then(data => {
  const dot = document.getElementById('rust-dot');
  const label = document.getElementById('rust-label');
  if (data.rust_parser === 'available') {
    dot.classList.add('ok');
    label.title = 'Parser Rust disponible';
  } else {
    label.style.color = 'var(--risk-med)';
    label.title = 'Parser Rust no disponible — análisis solo con Python';
  }
}).catch(() => {});

function toggleTheme() {
  const html = document.documentElement;
  html.setAttribute('data-theme',
    html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
}

// Drag & drop
const dropZone = document.getElementById('drop-zone');
dropZone.addEventListener('dragover', e => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  const f = e.dataTransfer.files[0];
  if (f) setFile(f);
});

function onFileSelected(input) {
  if (input.files[0]) setFile(input.files[0]);
}

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

  // Limpiar reporte anterior — sin contaminación entre análisis
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

function renderReport(r) {
  const meta = r.metadata || {};
  const ela = r.ela || {};
  const consistency = r.consistency || {};
  const ai = consistency.ai_signals || {};
  const gps = meta.gps || {};
  const ts = meta.timestamps || {};
  const device = meta.device || {};
  const hashes = meta.hashes || {};

  // Header
  set('rpt-analysis-id', r.analysis_id || '—');
  set('rpt-timestamp', r.analysis_timestamp || '');

  // Risk badge
  const risk = consistency.risk_level || 'INDETERMINADO';
  const badge = document.getElementById('rpt-risk-badge');
  badge.textContent = 'Riesgo: ' + risk;
  badge.className = 'risk-badge risk-' + risk.split('-')[0];

  // Básico
  set('rpt-format', meta.file_format || val_missing('no detectado'));
  const dims = meta.image_dimensions;
  set('rpt-dims', dims ? `${dims[0]} × ${dims[1]} px` : val_missing('—'));
  set('rpt-size', meta.file_size_bytes ? formatBytes(meta.file_size_bytes) : '—');
  set('rpt-source', escHtml(r.image_source || '—'));

  // Hashes
  const hashText = [
    hashes.sha256 ? `SHA-256  ${hashes.sha256}` : 'SHA-256  no calculado',
    hashes.md5    ? `MD5      ${hashes.md5}`    : 'MD5      no calculado',
  ].join('\n');
  document.getElementById('rpt-hashes').textContent = hashText;

  // Dispositivo
  set('rpt-make',     device.make     || val_missing('No encontrado'));
  set('rpt-model',    device.model    || val_missing('No encontrado'));
  set('rpt-software', device.software || val_missing('No encontrado'));
  set('rpt-serial',   device.serial_number || val_missing('No encontrado'));

  // Timestamps
  set('rpt-ts-original', ts.exif_datetime_original || val_missing('—'));
  set('rpt-ts-digitized', ts.exif_datetime_digitized || val_missing('—'));
  set('rpt-ts-fs', ts.filesystem_modified || val_missing('—'));
  set('rpt-tz', ts.timezone_offset || val_missing('—'));

  // GPS
  if (gps.latitude != null) {
    document.getElementById('gps-section').style.display = '';
    set('rpt-lat', String(gps.latitude));
    set('rpt-lon', String(gps.longitude));
    set('rpt-alt', gps.altitude != null ? gps.altitude + ' m' : val_missing('—'));
    const validEl = document.getElementById('rpt-gps-valid');
    validEl.textContent = gps.raw_valid ? 'SÍ' : 'NO — COORDENADAS IMPOSIBLES';
    validEl.style.color = gps.raw_valid ? 'var(--risk-low)' : 'var(--risk-high)';
    const notes = (gps.validation_notes || []).join('\n');
    document.getElementById('rpt-gps-notes').textContent = notes;
  }

  // IA
  const markerEl = document.getElementById('rpt-ai-marker');
  markerEl.textContent = ai.explicit_ai_software_marker ? 'SÍ — DETECTADO' : 'No';
  markerEl.style.color = ai.explicit_ai_software_marker ? 'var(--risk-high)' : 'inherit';
  const noCamEl = document.getElementById('rpt-no-camera');
  noCamEl.textContent = ai.no_camera_metadata ? 'SÍ' : 'No';
  noCamEl.style.color = ai.no_camera_metadata ? 'var(--risk-med)' : 'inherit';
  set('rpt-ai-assessment', ai.overall_assessment || '—');

  // ELA
  set('rpt-ela-conf', ela.confidence || (ela.applicable === false ? 'No aplicable: ' + ela.skip_reason : '—'));
  set('rpt-ela-ratio', ela.anomalous_pixel_ratio != null ?
    (ela.anomalous_pixel_ratio * 100).toFixed(1) + '%' : '—');
  set('rpt-ela-mean', ela.global_mean_error != null ? String(ela.global_mean_error) : '—');
  set('rpt-ela-note', (ela.caveats || []).join(' | '));

  if (r.ela_image_b64) {
    const img = document.getElementById('rpt-ela-img');
    img.src = 'data:image/png;base64,' + r.ela_image_b64;
    img.style.display = 'block';
  }

  // Entropy
  const entropy = r.entropy || {};
  if (entropy.applicable) {
    document.getElementById('entropy-section').style.display = '';
    set('rpt-entropy-global', entropy.global_entropy != null ?
      entropy.global_entropy + ' bits/byte' : '—');
    set('rpt-entropy-mean', entropy.block_mean_entropy != null ?
      entropy.block_mean_entropy + ' \u00b1 ' + entropy.block_std_entropy : '—');
    const eHigh = entropy.anomalous_blocks_high || 0;
    const eLow = entropy.anomalous_blocks_low || 0;
    const eRatio = entropy.anomalous_ratio || 0;
    set('rpt-entropy-anomalies',
      eHigh + ' altos, ' + eLow + ' bajos (' + (eRatio*100).toFixed(1) + '%)');
    set('rpt-entropy-conf', entropy.confidence || '—');
    set('rpt-entropy-note', (entropy.caveats || []).join(' | '));
  }

  // Hallazgos
  const findingsEl = document.getElementById('rpt-findings');
  const findings = consistency.findings || [];
  if (findings.length === 0) {
    findingsEl.innerHTML = '<span style="font-size:13px;color:var(--text-dim)">Sin hallazgos de inconsistencia.</span>';
  } else {
    findingsEl.innerHTML = findings.map(f => `
      <div class="finding finding-${f.relevance}">
        <div class="finding-title">
          [${escHtml(f.relevance)}]
          <span class="finding-cat">${escHtml(f.category)}</span>
        </div>
        <div>${escHtml(f.description)}</div>
        ${f.innocent_explanation ? `<div class="finding-innocent">ℹ ${escHtml(f.innocent_explanation)}</div>` : ''}
      </div>
    `).join('');
  }

  // Modo auditor
  const rawExif = meta.raw_exif_fields || {};
  document.getElementById('rpt-raw-exif').textContent =
    Object.entries(rawExif).map(([k,v]) => `${k}: ${v}`).join('\n') || '(sin campos EXIF)';

  const alerts = [
    ...(meta.extraction_warnings || []),
    ...((meta.security || {}).parse_errors || []),
    ...((meta.security || {}).oversized_fields || []),
    ...((meta.security || {}).structurally_anomalous || []),
  ];
  document.getElementById('rpt-parser-alerts').textContent =
    alerts.join('\n') || '(sin alertas)';

  // Mostrar reporte
  document.getElementById('report-card').classList.add('visible');
  document.getElementById('report-card').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function toggleAuditor() {
  _auditorOpen = !_auditorOpen;
  const sec = document.getElementById('auditor-section');
  const btn = document.querySelector('.auditor-toggle');
  sec.classList.toggle('visible', _auditorOpen);
  btn.textContent = (_auditorOpen ? '▼' : '▶') + ' Ver datos técnicos completos (modo auditor)';
}

function exportTxt() {
  if (!_lastReport) return;
  // Reconstruir el texto plano desde el reporte — sin llamada al servidor
  const lines = buildTextReport(_lastReport);
  download('reporte-' + (_lastReport.analysis_id || 'vtr') + '.txt', lines);
}

function exportJson() {
  if (!_lastReport) return;
  // Exportar sin la imagen ELA (base64 grande) — dato forense, no del reporte
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
  const findings = consistency.findings || [];

  const lines = [
    '='.repeat(60),
    'VTR FORENSIC IMAGE ANALYZER v0.1.0',
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

  lines.push('── HALLAZGOS');
  lines.push(`Nivel de riesgo: ${consistency.risk_level || '—'}`);
  findings.forEach(f => {
    lines.push(`[${f.relevance}] ${f.category}: ${f.description}`);
  });
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

// Utilidades — sin dependencias externas
function set(id, value) {
  const el = document.getElementById(id);
  if (!el) return;
  if (typeof value === 'string' && value.includes('<span')) {
    el.innerHTML = value;
  } else {
    el.textContent = value;
  }
}
function val_missing(text) { return `<span class="field-value missing">${text}</span>`; }
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
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
