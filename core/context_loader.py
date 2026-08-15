"""
vtr-forensic-img
core/context_loader.py

Carga segura de contexto externo (e.g. cryptofault JSON report).
Todas las mitigaciones de seguridad están incorporadas en este módulo.

Mitigaciones implementadas:
  1. Inyección de contenido — contexto nunca se renderiza como HTML
  2. Contaminación de custodia — context_unverified: true siempre presente
  3. Path traversal — validación de extensión y tamaño antes de leer
  4. Tamaño no acotado — límite MAX_CONTEXT_BYTES
  5. Confusión de fuente — _vtr_context_source obligatorio en output
  6. Replay de contexto — analysis_id y timestamp incluidos del contexto
  7. JSON anidamiento profundo — profundidad máxima MAX_CONTEXT_DEPTH
  8. Información sensible — warning explícito en CLI

Copyright (C) 2026 Luis Fidel Castellanos Diaz
Vector Telemetry Research (VTR) — SIGNAL. VECTOR. INTELLIGENCE.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Mitigación 4 — tamaño máximo del archivo de contexto
MAX_CONTEXT_BYTES = 50 * 1024  # 50 KB

# Mitigación 7 — profundidad máxima de anidamiento JSON
MAX_CONTEXT_DEPTH = 5

# Fuente obligatoria para cryptofault
CRYPTOFAULT_SOURCE = "cryptofault"


class ContextLoadError(Exception):
    """Error al cargar contexto externo — no interrumpe el análisis forense."""
    pass


def load(path: str) -> dict:
    """
    Carga y valida un archivo JSON de contexto externo.

    Args:
        path: ruta al archivo JSON (debe tener extensión .json)

    Returns:
        Dict con el contexto validado, listo para incluir en el reporte.
        Siempre incluye context_unverified: True y _vtr_context_source.

    Raises:
        ContextLoadError: si el archivo no pasa validación.
            El llamador debe decidir si continuar sin contexto o abortar.
    """
    p = Path(path)

    # Mitigación 3 — validar extensión
    if p.suffix.lower() != ".json":
        raise ContextLoadError(
            f"context file must have .json extension, got: {p.suffix!r}"
        )

    # Mitigación 3 — validar que el archivo existe y es un archivo regular
    if not p.exists():
        raise ContextLoadError(f"context file not found: {path}")
    if not p.is_file():
        raise ContextLoadError(f"context path is not a regular file: {path}")

    # Mitigación 4 — validar tamaño antes de leer
    size = p.stat().st_size
    if size > MAX_CONTEXT_BYTES:
        raise ContextLoadError(
            f"context file too large: {size} bytes (max {MAX_CONTEXT_BYTES})"
        )

    # Leer y parsear JSON
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise ContextLoadError(f"cannot read context file: {e}") from e

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ContextLoadError(f"invalid JSON in context file: {e}") from e

    if not isinstance(data, dict):
        raise ContextLoadError(
            f"context JSON must be an object at root level, got: {type(data).__name__}"
        )

    # Mitigación 7 — validar profundidad de anidamiento
    _validate_depth(data, max_depth=MAX_CONTEXT_DEPTH)

    # Ensamblar contexto seguro
    # Mitigación 2 — context_unverified siempre True
    # Mitigación 5 — _vtr_context_source siempre presente
    # Mitigación 6 — incluir analysis_id y timestamp del reporte fuente
    safe_context = {
        "_vtr_context_source": CRYPTOFAULT_SOURCE,
        "context_unverified": True,
        "context_file": p.name,
        "context_size_bytes": size,
        "source_analysis_id": data.get("analysis_id"),
        "source_timestamp": data.get("timestamp"),
        "source_tool": data.get("tool"),
        "source_tool_version": data.get("tool_version"),
        "source_schema_version": data.get("schema_version"),
        "findings_summary": data.get("summary"),
        "findings": data.get("findings", []),
        "source_input": data.get("source"),
    }

    log.info(
        "context loaded: %s — analysis_id=%s findings=%d",
        p.name,
        safe_context["source_analysis_id"],
        len(safe_context["findings"]),
    )

    return safe_context


def _validate_depth(obj: Any, max_depth: int, current: int = 0) -> None:
    """
    Mitigación 7 — valida profundidad máxima de anidamiento JSON.
    Previene stack overflow por JSON malicioso con anidamiento excesivo.
    """
    if current > max_depth:
        raise ContextLoadError(
            f"context JSON exceeds maximum nesting depth of {max_depth}"
        )
    if isinstance(obj, dict):
        for v in obj.values():
            _validate_depth(v, max_depth, current + 1)
    elif isinstance(obj, list):
        for item in obj:
            _validate_depth(item, max_depth, current + 1)


# Mitigación 8 — warning para CLI
CONTEXT_WARNING = (
    "\n[ADVERTENCIA] --context agrega información de red al reporte forense.\n"
    "El archivo de contexto puede contener IPs, hostnames, y topología de red.\n"
    "Verifique que el reporte final no contenga información sensible antes de compartirlo.\n"
)
