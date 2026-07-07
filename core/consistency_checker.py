"""
vtr-forensic-img v0.1.0
core/consistency_checker.py

Verificación de inconsistencias forenses entre los distintos campos
de metadata y las señales del análisis ELA.

La lógica central: una imagen auténtica de una cámara real tiene
un conjunto de propiedades que deben ser mutuamente consistentes.
Cuando no lo son, eso no prueba manipulación — pero sí justifica
investigación adicional. Cada inconsistencia detectada se etiqueta
con su nivel de relevancia forense (ALTA, MEDIA, BAJA) y con una
explicación de por qué puede ser significativa — o de por qué puede
tener también una explicación inocente.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .metadata_extractor import ImageMetadata

KNOWN_AI_SOFTWARE_MARKERS = [
    'stable diffusion', 'midjourney', 'dall-e', 'dall·e',
    'firefly', 'imagen', 'adobe firefly', 'nightcafe',
    'dreamstudio', 'leonardo.ai', 'bing image creator',
    'openai', 'runway', 'pika', 'sora',
]

KNOWN_EDITING_SOFTWARE = [
    'photoshop', 'lightroom', 'gimp', 'affinity photo',
    'capture one', 'darktable', 'rawtherapee', 'luminar',
    'snapseed', 'vsco', 'facetune',
]


@dataclass
class Finding:
    """Un hallazgo individual de consistency check."""
    category: str
    relevance: str  # ALTA / MEDIA / BAJA
    description: str
    field_source: str
    innocent_explanation: str = ""


@dataclass
class AISignals:
    """Señales específicas de imagen generada por IA."""
    explicit_ai_software_marker: bool = False
    software_detected: list[str] = field(default_factory=list)
    no_camera_metadata: bool = False
    no_gps_ever: bool = False
    no_capture_settings: bool = False
    overall_assessment: str = ""


@dataclass
class ConsistencyReport:
    findings: list[Finding] = field(default_factory=list)
    ai_signals: AISignals = field(default_factory=AISignals)
    timestamp_anomalies: list[str] = field(default_factory=list)
    provenance_summary: str = ""
    risk_level: str = "INDETERMINADO"


def _parse_exif_datetime(dt_str: str | None) -> datetime | None:
    if not dt_str:
        return None
    for fmt in ('%Y:%m:%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S'):
        try:
            return datetime.strptime(dt_str.strip(), fmt)
        except ValueError:
            continue
    return None


def _check_timestamps(meta: ImageMetadata, report: ConsistencyReport) -> None:
    ts = meta.timestamps

    dt_original = _parse_exif_datetime(ts.exif_datetime_original)
    dt_modified = _parse_exif_datetime(ts.exif_datetime_modified)
    dt_digitized = _parse_exif_datetime(ts.exif_datetime_digitized)
    dt_fs_modified = _parse_exif_datetime(ts.filesystem_modified)

    # Modificado antes de creado en EXIF — imposible en condiciones normales
    if dt_original and dt_modified:
        if dt_modified < dt_original:
            report.findings.append(Finding(
                category="Timestamps",
                relevance="ALTA",
                description=(
                    f"DateTime Modified ({ts.exif_datetime_modified}) es anterior "
                    f"a DateTimeOriginal ({ts.exif_datetime_original}) — un archivo "
                    f"no puede modificarse antes de ser creado."
                ),
                field_source="EXIF DateTimeOriginal / DateTime",
                innocent_explanation=(
                    "Puede ocurrir si el reloj del dispositivo estaba mal configurado "
                    "al momento de la captura, o si los campos fueron editados "
                    "manualmente con posterioridad."
                )
            ))
            report.timestamp_anomalies.append(
                "Modified < Original en EXIF — inconsistencia cronológica"
            )

    # EXIF Original anterior al filesystem modified por más de 1 hora
    if dt_original and dt_fs_modified:
        delta = abs((dt_fs_modified - dt_original).total_seconds())
        if delta > 3600 * 24 * 7:
            report.findings.append(Finding(
                category="Timestamps",
                relevance="MEDIA",
                description=(
                    f"DateTimeOriginal ({ts.exif_datetime_original}) difiere del "
                    f"timestamp de modificación del filesystem ({ts.filesystem_modified}) "
                    f"en más de 7 días ({delta/86400:.1f} días)."
                ),
                field_source="EXIF DateTimeOriginal / filesystem mtime",
                innocent_explanation=(
                    "Normal si la imagen fue copiada, enviada por mensajería, "
                    "o descargada de internet — el filesystem mtime refleja "
                    "cuándo se guardó en este disco, no cuándo fue capturada."
                )
            ))

    # Digitized muy distinto de Original (imágenes digitalizadas de papel)
    if dt_original and dt_digitized:
        delta = abs((dt_digitized - dt_original).total_seconds())
        if delta > 60:
            report.findings.append(Finding(
                category="Timestamps",
                relevance="BAJA",
                description=(
                    f"DateTimeOriginal ({ts.exif_datetime_original}) difiere de "
                    f"DateTimeDigitized ({ts.exif_datetime_digitized}) en "
                    f"{delta:.0f} segundos — puede indicar digitalización de "
                    f"un documento físico (relevante para contexto genealógico)."
                ),
                field_source="EXIF DateTimeOriginal / DateTimeDigitized",
                innocent_explanation=(
                    "Completamente normal en imágenes de documentos históricos "
                    "digitalizados: Original es la fecha del documento, "
                    "Digitized es cuando fue escaneado."
                )
            ))
            report.timestamp_anomalies.append(
                f"Original ≠ Digitized por {delta:.0f}s — posible documento digitalizado"
            )


def _check_ai_signals(meta: ImageMetadata, report: ConsistencyReport) -> None:
    ai = report.ai_signals

    # Señal 1: software explícitamente marcado como IA
    all_software = []
    if meta.device.software:
        all_software.append(meta.device.software.lower())
    for sw in meta.editing.software_used:
        all_software.append(sw.lower())
    for key, val in meta.png_text_chunks.items():
        if 'software' in key.lower() or 'comment' in key.lower():
            all_software.append(val.lower())

    for sw in set(all_software):  # set() elimina duplicados antes de iterar
        for marker in KNOWN_AI_SOFTWARE_MARKERS:
            if marker in sw:
                ai.explicit_ai_software_marker = True
                ai.software_detected.append(sw)
                report.findings.append(Finding(
                    category="IA Generativa",
                    relevance="ALTA",
                    description=(
                        f"Software identificado en metadata: '{sw}'. "
                        f"Este valor coincide con un generador de imagen "
                        f"conocido por IA — la imagen puede haber sido "
                        f"generada sintéticamente, no capturada."
                    ),
                    field_source="Image Software / PNG Software chunk",
                    innocent_explanation=(
                        "Puede ser falso positivo si el software de generación "
                        "fue usado solo para post-procesamiento de una imagen real, "
                        "no para generarla desde cero."
                    )
                ))

    # Señal 2: ausencia total de metadata de cámara
    has_camera_make = bool(meta.device.make)
    has_camera_model = bool(meta.device.model)
    has_capture = any([
        meta.capture.iso,
        meta.capture.aperture,
        meta.capture.shutter_speed,
    ])
    has_gps = (
        meta.gps.latitude is not None or
        meta.gps.longitude is not None
    )

    if not has_camera_make and not has_camera_model and not has_capture:
        ai.no_camera_metadata = True
        report.findings.append(Finding(
            category="IA Generativa",
            relevance="MEDIA",
            description=(
                "No se encontró ningún campo de metadata de cámara: ni fabricante, "
                "ni modelo, ni parámetros de captura (ISO, apertura, velocidad). "
                "Las imágenes generadas por IA típicamente carecen de estos campos "
                "porque no existe un dispositivo de captura real."
            ),
            field_source="Image Make / Image Model / EXIF ISOSpeedRatings / FNumber / ExposureTime",
            innocent_explanation=(
                "También puede ocurrir en: imágenes escaneadas de documentos "
                "(los escáneres típicamente no generan estos campos), screenshots, "
                "imágenes descargadas de web con metadata eliminada, o imágenes "
                "procesadas con herramientas que eliminan metadata por defecto."
            )
        ))

    ai.no_gps_ever = not has_gps
    ai.no_capture_settings = not has_capture

    # Señal 3: software de edición presente sin metadata de captura
    has_editing_software = any(
        any(ed in sw.lower() for ed in KNOWN_EDITING_SOFTWARE)
        for sw in [meta.device.software or ''] + meta.editing.software_used
    )

    if has_editing_software and not has_capture:
        report.findings.append(Finding(
            category="Edición",
            relevance="MEDIA",
            description=(
                f"Software de edición detectado en metadata, pero sin parámetros "
                f"de captura. Software: {', '.join(meta.editing.software_used or [meta.device.software or 'desconocido'])}."
            ),
            field_source="Image Software",
            innocent_explanation=(
                "Normal en imágenes que fueron procesadas desde un RAW y luego "
                "exportadas sin preservar los parámetros originales de captura."
            )
        ))

    # Assessment de IA
    if ai.explicit_ai_software_marker:
        ai.overall_assessment = (
            "SEÑAL DIRECTA DE IA: software de generación identificado en metadata."
        )
    elif ai.no_camera_metadata and not meta.editing.software_used:
        ai.overall_assessment = (
            "AUSENCIA TOTAL DE METADATA DE CAPTURA: consistente con imagen "
            "generada por IA o con documento digitalizado. Requiere contexto adicional."
        )
    elif ai.no_camera_metadata:
        ai.overall_assessment = (
            "Sin metadata de cámara, con software de edición presente. "
            "La proveniencia original no es determinable solo por metadata."
        )
    else:
        ai.overall_assessment = (
            "Metadata de cámara presente. No se detectaron marcadores directos "
            "de generación por IA — la imagen tiene la estructura esperada de "
            "una captura real, aunque la metadata puede haber sido añadida "
            "o modificada post-generación."
        )


def _check_gps_consistency(meta: ImageMetadata, report: ConsistencyReport) -> None:
    if not meta.gps.raw_valid:
        for note in meta.gps.validation_notes:
            report.findings.append(Finding(
                category="GPS",
                relevance="ALTA",
                description=f"Coordenada GPS físicamente imposible: {note}",
                field_source="GPS EXIF",
                innocent_explanation=(
                    "Puede ser error de hardware en el receptor GPS del dispositivo, "
                    "o metadata generada/modificada programáticamente."
                )
            ))

    if meta.gps.latitude is not None and meta.timestamps.timezone_offset:
        try:
            lon = meta.gps.longitude or 0
            expected_utc_offset = round(lon / 15)
            actual_offset_str = meta.timestamps.timezone_offset.replace(':', '')
            actual_offset = int(actual_offset_str[:3]) if len(actual_offset_str) >= 3 else None

            if actual_offset is not None and abs(expected_utc_offset - actual_offset) > 2:
                report.findings.append(Finding(
                    category="GPS / Timezone",
                    relevance="MEDIA",
                    description=(
                        f"El offset de timezone del dispositivo ({meta.timestamps.timezone_offset}) "
                        f"no corresponde a la longitud GPS ({lon:.2f}° → UTC{expected_utc_offset:+d} esperado). "
                        f"El dispositivo puede estar configurado en una zona horaria "
                        f"distinta a donde fue capturada la imagen."
                    ),
                    field_source="EXIF OffsetTimeOriginal / GPS GPSLongitude",
                    innocent_explanation=(
                        "Completamente normal para viajeros cuyo dispositivo mantiene "
                        "la zona horaria de origen, o para imágenes capturadas cerca "
                        "de fronteras de zona horaria."
                    )
                ))
        except Exception:
            pass


def _check_thumbnail(meta: ImageMetadata, report: ConsistencyReport) -> None:
    if meta.editing.has_thumbnail and meta.image_dimensions and meta.editing.thumbnail_size:
        th_w, th_h = meta.editing.thumbnail_size
        img_w, img_h = meta.image_dimensions

        th_ratio = th_w / th_h if th_h > 0 else 0
        img_ratio = img_w / img_h if img_h > 0 else 0

        if abs(th_ratio - img_ratio) > 0.05:
            report.findings.append(Finding(
                category="Thumbnail",
                relevance="ALTA",
                description=(
                    f"Relación de aspecto del thumbnail embebido ({th_w}x{th_h}, "
                    f"ratio {th_ratio:.3f}) difiere significativamente de la imagen "
                    f"principal ({img_w}x{img_h}, ratio {img_ratio:.3f}). "
                    f"El thumbnail puede mostrar el contenido original antes de un "
                    f"recorte o edición posterior."
                ),
                field_source="EXIF JPEGThumbnail",
                innocent_explanation=(
                    "Puede ocurrir si la imagen fue rotada o recortada después de "
                    "ser capturada, sin que se actualizara el thumbnail embebido."
                )
            ))


def _build_provenance_summary(meta: ImageMetadata, report: ConsistencyReport) -> None:
    lines = []

    if meta.device.make or meta.device.model:
        device_str = " ".join(filter(None, [meta.device.make, meta.device.model]))
        lines.append(f"Dispositivo de captura: {device_str}")
    else:
        lines.append("Dispositivo de captura: no identificado en metadata")

    if meta.timestamps.exif_datetime_original:
        lines.append(f"Fecha de captura (EXIF): {meta.timestamps.exif_datetime_original}")

    if meta.timestamps.filesystem_modified:
        lines.append(f"Última modificación en disco: {meta.timestamps.filesystem_modified}")

    if meta.gps.latitude is not None and meta.gps.longitude is not None:
        lines.append(
            f"Ubicación GPS: {meta.gps.latitude:.6f}, {meta.gps.longitude:.6f}"
            f"{' (COORDENADAS INVÁLIDAS)' if not meta.gps.raw_valid else ''}"
        )

    if meta.editing.software_used:
        lines.append(f"Software detectado: {', '.join(meta.editing.software_used)}")

    alta_count = sum(1 for f in report.findings if f.relevance == "ALTA")
    media_count = sum(1 for f in report.findings if f.relevance == "MEDIA")

    if alta_count > 0:
        report.risk_level = "ALTO"
    elif media_count >= 2:
        report.risk_level = "MEDIO"
    elif media_count == 1:
        report.risk_level = "BAJO-MEDIO"
    else:
        report.risk_level = "BAJO"

    lines.append(
        f"\nNivel de riesgo forense: {report.risk_level} "
        f"({alta_count} hallazgos de relevancia ALTA, "
        f"{media_count} de relevancia MEDIA)"
    )

    report.provenance_summary = "\n".join(lines)


def check(meta: ImageMetadata) -> ConsistencyReport:
    """
    Ejecuta todos los checks de consistencia sobre un ImageMetadata
    ya extraído. Retorna ConsistencyReport con los hallazgos ordenados
    por relevancia forense.
    """
    report = ConsistencyReport()

    _check_timestamps(meta, report)
    _check_ai_signals(meta, report)
    _check_gps_consistency(meta, report)
    _check_thumbnail(meta, report)
    _build_provenance_summary(meta, report)

    report.findings.sort(
        key=lambda f: {'ALTA': 0, 'MEDIA': 1, 'BAJA': 2}.get(f.relevance, 3)
    )

    return report
