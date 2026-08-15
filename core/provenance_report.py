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
from datetime import datetime, timezone
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
    context: dict | None = None,
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
        "vtr_forensic_version": "0.3.0",
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
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

    # 2b. Entropía de Shannon por bloques (incluye EntropyProfile v0.3.0)
    from .entropy_analyzer import analyze as entropy_analyze
    entropy_result = entropy_analyze(image_source)
    report["entropy"] = _dataclass_to_dict(entropy_result)

    # 2c. Tablas de cuantización JPEG (v0.3.0)
    from .quantization_analyzer import analyze as quant_analyze
    quant_result = quant_analyze(image_source)
    report["quantization"] = _dataclass_to_dict(quant_result)

    # 2d. Análisis de frecuencia FFT (v0.3.0)
    from .frequency_analyzer import analyze as freq_analyze
    freq_result = freq_analyze(image_source)
    report["frequency"] = _dataclass_to_dict(freq_result)

    # 2e. Consistencia de ruido PRNU (v0.3.0)
    from .noise_analyzer import analyze as noise_analyze
    noise_result = noise_analyze(image_source)
    report["noise"] = _dataclass_to_dict(noise_result)

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

    # Contexto externo — Nivel 1 integración ecosistema VTR
    if context is not None:
        report["external_context"] = context
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

    entropy = report.get("entropy", {})
    lines += [
        "── ENTROPÍA DE SHANNON (por bloques) ────────────────────────────",
    ]
    if entropy.get("applicable"):
        lines += [
            f"  Entropía global:   {entropy.get('global_entropy')} bits/byte",
            f"  Media bloques:     {entropy.get('block_mean_entropy')} ± {entropy.get('block_std_entropy')}",
            f"  Rango:             [{entropy.get('block_min_entropy')} — {entropy.get('block_max_entropy')}]",
            f"  Bloques anómalos:  {entropy.get('anomalous_blocks_high', 0)} altos, "
            f"{entropy.get('anomalous_blocks_low', 0)} bajos "
            f"({entropy.get('anomalous_ratio', 0)*100:.1f}%)",
            f"  Confianza:         {entropy.get('confidence', 'N/D')}",
        ]
        for caveat in entropy.get("caveats", []):
            lines.append(f"  ⚠ {caveat}")
    else:
        lines.append(f"  No aplicable: {entropy.get('skip_reason', 'N/D')}")
    lines.append("")

    # EntropyProfile v0.3.0
    profile = entropy.get("profile")
    if profile and isinstance(profile, dict):
        lines += [
            "── PERFIL DE ENTROPÍA (caracterización IA) ──────────────────────",
            f"  Skewness:      {profile.get('skewness', 'N/D')}",
            f"  Kurtosis:      {profile.get('kurtosis', 'N/D')} (foto real: >3.0)",
            f"  Gradiente esp.: {profile.get('spatial_gradient_mean', 'N/D')} ± {profile.get('spatial_gradient_std', 'N/D')}",
            f"  Canal R:        {profile.get('channel_entropy_r', 'N/D')} bits/byte",
            f"  Canal G:        {profile.get('channel_entropy_g', 'N/D')} bits/byte",
            f"  Canal B:        {profile.get('channel_entropy_b', 'N/D')} bits/byte",
            f"  Corr R-G:       {profile.get('channel_correlation_rg', 'N/D')}",
            f"  Corr R-B:       {profile.get('channel_correlation_rb', 'N/D')}",
            f"  Corr G-B:       {profile.get('channel_correlation_gb', 'N/D')}",
            f"  Multi-escala:   32={profile.get('multiscale_32_mean', 'N/D')} | "
            f"64={profile.get('multiscale_64_mean', 'N/D')} | "
            f"128={profile.get('multiscale_128_mean', 'N/D')}",
            f"  IA confianza:   {profile.get('ai_confidence', 'N/D')}",
        ]
        for ind in profile.get("ai_indicators", []):
            lines.append(f"  ⚠ {ind}")
        lines.append("")

    # Cuantización JPEG (v0.3.0)
    quant = report.get("quantization", {})
    lines += [
        "── TABLAS DE CUANTIZACIÓN JPEG ──────────────────────────────────",
    ]
    if quant.get("applicable"):
        lines += [
            f"  Tablas encontradas: {quant.get('num_tables', 0)}",
            f"  Calidad estimada:   {quant.get('estimated_quality', 'N/D')}%",
            f"  Escalado estándar:  {'SÍ (software/IA)' if quant.get('is_standard_table') else 'NO (cámara/especializado)'}",
        ]
        match = quant.get("matches_known_library")
        if match:
            lines.append(f"  Coincide con:       {match}")
        lines.append(f"  Relevancia IA:      {quant.get('ai_relevant', 'N/D')}")
        for f in quant.get("findings", []):
            lines.append(f"  → {f}")
    else:
        lines.append(f"  No aplicable: {quant.get('skip_reason', 'N/D')}")
    lines.append("")

    # Frecuencia FFT (v0.3.0)
    freq = report.get("frequency", {})
    lines += [
        "── ANÁLISIS DE FRECUENCIA (FFT) ─────────────────────────────────",
    ]
    if freq.get("applicable"):
        lines += [
            f"  Pendiente espectral: {freq.get('spectral_slope', 'N/D')} (foto real: -2.0 a -3.0)",
            f"  R² del ajuste:      {freq.get('slope_r_squared', 'N/D')}",
            f"  Energía alta freq:  {(freq.get('high_freq_energy_ratio', 0) or 0)*100:.1f}%",
            f"  Picos periódicos:   {freq.get('periodic_peaks_detected', 0)}",
            f"  Simetría espectral: {freq.get('spectral_symmetry', 'N/D')}",
            f"  Relevancia IA:      {freq.get('ai_relevant', 'N/D')}",
        ]
        for caveat in freq.get("caveats", []):
            lines.append(f"  ⚠ {caveat}")
    else:
        lines.append(f"  No aplicable: {freq.get('skip_reason', 'N/D')}")
    lines.append("")

    # Ruido PRNU (v0.3.0)
    noise = report.get("noise", {})
    lines += [
        "── CONSISTENCIA DE RUIDO (PRNU) ─────────────────────────────────",
    ]
    if noise.get("applicable"):
        lines += [
            f"  Ruido std:          {noise.get('noise_std', 'N/D')}",
            f"  Uniformidad var.:   {noise.get('variance_uniformity', 'N/D')} (sensor real: 0.2-0.8)",
            f"  Gaussiano:          {'SÍ' if noise.get('is_gaussian_like') else 'NO' if noise.get('is_gaussian_like') is False else 'N/D'}",
            f"  Corr inter-regional: {noise.get('cross_region_correlation', 'N/D')}",
            f"  Ruido R/G/B:        {noise.get('noise_std_r', 'N/D')} / {noise.get('noise_std_g', 'N/D')} / {noise.get('noise_std_b', 'N/D')}",
            f"  Ratio B/G:          {noise.get('channel_noise_ratio_bg', 'N/D')} (sensor CMOS: >1.1)",
            f"  Relevancia IA:      {noise.get('ai_relevant', 'N/D')}",
        ]
        for caveat in noise.get("caveats", []):
            lines.append(f"  ⚠ {caveat}")
    else:
        lines.append(f"  No aplicable: {noise.get('skip_reason', 'N/D')}")
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
