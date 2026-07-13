"""
vtr-forensic-img v0.1.0
core/provenance_report.py

Ensambla el reporte forense completo combinando los tres módulos:
metadata_extractor, ela_analyzer, y consistency_checker.
"""

from __future__ import annotations

import base64
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from .consistency_checker import ConsistencyReport, check
from .ela_analyzer import ELAResult, analyze as ela_analyze
from .metadata_extractor import ImageMetadata, extract


def _dataclass_to_dict(obj) -> dict:
    """Convierte dataclasses anidadas a dict serializable, manejando bytes."""
    if hasattr(obj, '__dataclass_fields__'):
        result = {}
        for k, v in asdict(obj).items():
            if isinstance(v, bytes):
                result[k] = f"<bytes:{len(v)}>"
            else:
                result[k] = v
        return result
    return str(obj)


def generate(
    image_source: str | Path,
    ela_quality: int = 95,
    ela_threshold: float = 15.0,
    include_ela_image: bool = True,
    strict: bool = False,
) -> dict:
    """
    Genera el reporte forense completo para una imagen.

    Args:
        strict: si True, el análisis se detiene al primer error
            estructural. Ver core/strict_mode.py.

    Returns:
        Dict con toda la información del análisis, serializable a JSON.
        Si el módulo de reporte web lo consume, convierte la imagen ELA
        a base64 para incrustarla directamente en el HTML.

    Raises:
        StrictModeViolation: solo en modo estricto, cuando cualquier
            campo no cumple la especificación.
    """
    report = {
        "vtr_forensic_version": "0.2.0",
        "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
        "image_source": str(image_source),
        "strict_mode": strict,
        "metadata": {},
        "ela": {},
        "consistency": {},
        "ela_image_b64": None,
    }

    # 1. Extracción de metadata
    meta: ImageMetadata = extract(image_source, strict=strict)
    report["metadata"] = _dataclass_to_dict(meta)

    # 2. ELA
    ela_result: ELAResult = ela_analyze(
        image_source,
        quality=ela_quality,
        threshold=ela_threshold,
        include_ela_image=include_ela_image,
    )
    ela_bytes = ela_result.ela_image_bytes
    ela_result.ela_image_bytes = None  # no serializar bytes crudos en JSON
    report["ela"] = _dataclass_to_dict(ela_result)

    if ela_bytes:
        report["ela_image_b64"] = base64.b64encode(ela_bytes).decode('ascii')

    # 3. Consistency checks
    consistency: ConsistencyReport = check(meta)
    report["consistency"] = _dataclass_to_dict(consistency)

    # Asegurar que sha256/md5 están siempre en metadata.hashes
    # independientemente de si vienen del parser Python o del Rust bridge
    if "metadata" in report:
        meta_dict = report["metadata"]
        if not meta_dict.get("hashes") or not meta_dict["hashes"].get("sha256"):
            report["metadata"]["hashes"] = {
                "sha256": meta_dict.get("sha256") or "",
                "md5": meta_dict.get("md5") or "",
            }

    return report


def to_json(report: dict, indent: int = 2) -> str:
    return json.dumps(report, ensure_ascii=False, indent=indent, default=str)


def to_text(report: dict) -> str:
    """Formato de texto plano para la salida del CLI."""
    lines = [
        "=" * 70,
        "VTR FORENSIC IMAGE ANALYZER v0.1.0",
        "=" * 70,
        f"Archivo:    {report['image_source']}",
        f"Análisis:   {report['analysis_timestamp']}",
        "",
    ]

    meta = report.get("metadata", {})
    lines += [
        "── INFORMACIÓN BÁSICA ────────────────────────────────────────────",
        f"  Formato:       {meta.get('file_format', 'N/D')}",
        f"  Dimensiones:   {meta.get('image_dimensions', 'N/D')}",
        f"  Tamaño:        {meta.get('file_size_bytes', 0):,} bytes",
        f"  SHA-256:       {meta.get('sha256', 'N/D')}",
        f"  MD5:           {meta.get('md5', 'N/D')}",
        "",
    ]

    device = meta.get("device", {})
    lines += [
        "── DISPOSITIVO ───────────────────────────────────────────────────",
        f"  Fabricante:    {device.get('make', 'No encontrado')}",
        f"  Modelo:        {device.get('model', 'No encontrado')}",
        f"  Software:      {device.get('software', 'No encontrado')}",
        f"  Nº Serie:      {device.get('serial_number', 'No encontrado')}",
        "",
    ]

    ts = meta.get("timestamps", {})
    lines += [
        "── TIMESTAMPS ────────────────────────────────────────────────────",
        f"  EXIF Original: {ts.get('exif_datetime_original', 'No encontrado')}",
        f"  EXIF Digit.:   {ts.get('exif_datetime_digitized', 'No encontrado')}",
        f"  EXIF Modif.:   {ts.get('exif_datetime_modified', 'No encontrado')}",
        f"  FS Modif.:     {ts.get('filesystem_modified', 'No encontrado')}",
        f"  FS Creado:     {ts.get('filesystem_created', 'No encontrado')}",
        f"  Timezone:      {ts.get('timezone_offset', 'No encontrado')}",
        "",
    ]

    gps = meta.get("gps", {})
    if gps.get("latitude") is not None:
        lines += [
            "── GPS ───────────────────────────────────────────────────────────",
            f"  Latitud:       {gps.get('latitude')}",
            f"  Longitud:      {gps.get('longitude')}",
            f"  Altitud:       {gps.get('altitude')} m",
            f"  Válido:        {'SÍ' if gps.get('raw_valid') else 'NO — COORDENADAS IMPOSIBLES'}",
        ]
        for note in gps.get("validation_notes", []):
            lines.append(f"  ⚠ {note}")
        lines.append("")

    ela = report.get("ela", {})
    lines += [
        "── ELA (Error Level Analysis) ────────────────────────────────────",
    ]
    if ela.get("applicable"):
        lines += [
            f"  Error medio:   {ela.get('global_mean_error')}",
            f"  Error máx:     {ela.get('global_max_error')}",
            f"  Desv. estándar:{ela.get('global_std_error')}",
            f"  Bloques anóm.: {ela.get('anomalous_pixel_ratio', 0)*100:.1f}%",
            f"  Umbral usado:  {ela.get('threshold_used')}",
            f"  Confianza:     {ela.get('confidence', 'N/D')}",
            f"  Interpretación: {ela.get('interpretation', 'N/D')}",
        ]
        for caveat in ela.get("caveats", []):
            lines.append(f"  ⚠ {caveat}")
    else:
        lines.append(f"  No aplicable: {ela.get('skip_reason', 'N/D')}")
    lines.append("")

    consistency = report.get("consistency", {})
    findings = consistency.get("findings", [])
    risk = consistency.get("risk_level", "INDETERMINADO")

    lines += [
        "── HALLAZGOS DE CONSISTENCIA ─────────────────────────────────────",
        f"  Nivel de riesgo: {risk}",
        "",
    ]

    if findings:
        for f in findings:
            rel = f.get("relevance", "?")
            cat = f.get("category", "")
            desc = f.get("description", "")
            innocent = f.get("innocent_explanation", "")
            lines.append(f"  [{rel}] {cat}")
            lines.append(f"    {desc}")
            if innocent:
                lines.append(f"    Explicación inocente: {innocent}")
            lines.append("")
    else:
        lines.append("  Sin hallazgos de inconsistencia.")
        lines.append("")

    ai = consistency.get("ai_signals", {})
    lines += [
        "── SEÑALES DE IA GENERATIVA ──────────────────────────────────────",
        f"  Evaluación: {ai.get('overall_assessment', 'N/D')}",
        f"  Marcador explícito: {'SÍ' if ai.get('explicit_ai_software_marker') else 'No'}",
        f"  Sin metadata de cámara: {'SÍ' if ai.get('no_camera_metadata') else 'No'}",
        "",
    ]

    prov = consistency.get("provenance_summary", "")
    if prov:
        lines += [
            "── RESUMEN DE PROVENIENCIA ───────────────────────────────────────",
        ]
        for line in prov.split("\n"):
            lines.append(f"  {line}")
        lines.append("")

    warnings = meta.get("extraction_warnings", [])
    errors = meta.get("security", {}).get("parse_errors", [])
    oversized = meta.get("security", {}).get("oversized_fields", [])
    non_print = meta.get("security", {}).get("non_printable_chars_in_fields", [])

    if any([warnings, errors, oversized, non_print]):
        lines.append("── ALERTAS DE SEGURIDAD DEL PARSER ──────────────────────────────")
        for w in warnings:
            lines.append(f"  ⚠ ADVERTENCIA: {w}")
        for e in errors:
            lines.append(f"  ✗ ERROR PARSE: {e}")
        for o in oversized:
            lines.append(f"  ⚠ CAMPO LARGO: {o}")
        for n in non_print:
            lines.append(f"  ⚠ CHARS ANÓMALOS: {n}")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)
