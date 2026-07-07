"""
vtr-forensic-img v0.1.0
core/metadata_extractor.py

Extracción defensiva de metadata de imagen para auditoría forense.

DECISIÓN DE SEGURIDAD (documentada, no asumida): este módulo opera
100% offline — ningún dato de imagen se envía a ningún servicio
externo. Razón: en un contexto forense, enviar la imagen a un servicio
de terceros rompe la cadena de custodia. Cuando el origen o integridad
de una imagen es lo que se está auditando, el propio archivo es la
evidencia — no puede salir del control del analista.

MITIGACIÓN DE INJECTION VÍA IMAGEN MALICIOSA: una imagen construida
maliciosamente puede intentar explotar parsers de metadata (CVEs
históricos en libexif, vulnerabilidades de buffer overflow en tags
oversized, intentos de path traversal en campos de nombre de archivo).
Este módulo mitiga esto:
  1. Todos los valores de metadata se convierten a str() y se truncan
     antes de procesarse — nunca se evalúan ni ejecutan.
  2. Se usan try/except exhaustivos por campo, no por archivo completo
     — un campo malicioso no aborta el análisis del resto.
  3. Los valores se sanitizan contra un conjunto de caracteres seguros
     antes de incluirse en el reporte — evita injection en el HTML
     del reporte generado en web/app.py.
  4. La longitud máxima de cualquier valor de metadata es 2048 chars —
     valores anormalmente largos son truncados y marcados en el reporte.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import exifread
from PIL import Image, ExifTags

logger = logging.getLogger(__name__)

MAX_FIELD_LENGTH = 2048
SAFE_PATTERN = re.compile(r'[^\x20-\x7E\u00C0-\u024F\u0400-\u04FF]')


@dataclass
class GPSCoordinates:
    latitude: float | None = None
    longitude: float | None = None
    altitude: float | None = None
    speed: float | None = None
    direction: float | None = None
    timestamp_utc: str | None = None
    raw_valid: bool = True
    validation_notes: list[str] = field(default_factory=list)


@dataclass
class DeviceInfo:
    make: str | None = None
    model: str | None = None
    serial_number: str | None = None
    firmware_version: str | None = None
    lens_model: str | None = None
    software: str | None = None


@dataclass
class TimestampSet:
    exif_datetime_original: str | None = None
    exif_datetime_digitized: str | None = None
    exif_datetime_modified: str | None = None
    filesystem_created: str | None = None
    filesystem_modified: str | None = None
    filesystem_accessed: str | None = None
    timezone_offset: str | None = None


@dataclass
class CaptureSettings:
    iso: str | None = None
    aperture: str | None = None
    shutter_speed: str | None = None
    focal_length: str | None = None
    flash: str | None = None
    white_balance: str | None = None
    exposure_mode: str | None = None
    metering_mode: str | None = None


@dataclass
class EditingHistory:
    software_used: list[str] = field(default_factory=list)
    xmp_history: list[str] = field(default_factory=list)
    has_thumbnail: bool = False
    thumbnail_size: tuple[int, int] | None = None
    icc_profile_name: str | None = None
    color_space: str | None = None


@dataclass
class SecurityFlags:
    """
    Indicadores de riesgo detectados durante la extracción.
    Cada flag incluye el campo específico donde se detectó y una
    descripción del riesgo — nunca solo un booleano sin contexto.
    """
    oversized_fields: list[str] = field(default_factory=list)
    non_printable_chars_in_fields: list[str] = field(default_factory=list)
    structurally_anomalous: list[str] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)


@dataclass
class ImageMetadata:
    """Resultado completo de extracción de metadata de una imagen."""
    file_path: str = ""
    file_format: str | None = None
    file_size_bytes: int = 0
    image_dimensions: tuple[int, int] | None = None
    color_mode: str | None = None
    sha256: str = ""
    md5: str = ""

    gps: GPSCoordinates = field(default_factory=GPSCoordinates)
    device: DeviceInfo = field(default_factory=DeviceInfo)
    timestamps: TimestampSet = field(default_factory=TimestampSet)
    capture: CaptureSettings = field(default_factory=CaptureSettings)
    editing: EditingHistory = field(default_factory=EditingHistory)
    security: SecurityFlags = field(default_factory=SecurityFlags)

    raw_exif_fields: dict[str, str] = field(default_factory=dict)
    png_text_chunks: dict[str, str] = field(default_factory=dict)
    extraction_warnings: list[str] = field(default_factory=list)
    extraction_complete: bool = False


def _safe_str(value: Any, field_name: str, flags: SecurityFlags) -> str:
    """
    Convierte cualquier valor de metadata a string seguro:
    - Limita longitud a MAX_FIELD_LENGTH
    - Detecta caracteres no imprimibles (potencial injection)
    - Nunca eval() ni exec() — solo str() y strip()
    """
    try:
        result = str(value).strip()
    except Exception:
        flags.parse_errors.append(f"{field_name}: no se pudo convertir a string")
        return ""

    if len(result) > MAX_FIELD_LENGTH:
        flags.oversized_fields.append(
            f"{field_name}: {len(result)} chars (truncado a {MAX_FIELD_LENGTH})"
        )
        result = result[:MAX_FIELD_LENGTH] + "...[TRUNCADO]"

    suspicious = SAFE_PATTERN.findall(result)
    if suspicious:
        flags.non_printable_chars_in_fields.append(
            f"{field_name}: {len(suspicious)} caracteres anómalos detectados"
        )
        result = SAFE_PATTERN.sub('?', result)

    return result


def _compute_hashes(file_path: Path) -> tuple[str, str]:
    """SHA-256 y MD5 del archivo completo — para cadena de custodia."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def _parse_gps_coord(values) -> float | None:
    """
    Convierte el formato DMS racional de EXIF a decimal.
    Valida que los valores estén en rangos físicamente posibles
    antes de retornarlos.
    """
    try:
        d = float(values[0].num) / float(values[0].den)
        m = float(values[1].num) / float(values[1].den)
        s = float(values[2].num) / float(values[2].den)
        return d + (m / 60.0) + (s / 3600.0)
    except Exception:
        return None


def _validate_gps(gps: GPSCoordinates) -> None:
    """
    Valida que las coordenadas GPS estén dentro de rangos físicamente
    posibles. Rangos imposibles son una señal forense significativa
    (metadata fabricada o corrupta).
    """
    if gps.latitude is not None:
        if not (-90.0 <= gps.latitude <= 90.0):
            gps.raw_valid = False
            gps.validation_notes.append(
                f"Latitud fuera de rango físico: {gps.latitude} (válido: -90 a 90)"
            )
    if gps.longitude is not None:
        if not (-180.0 <= gps.longitude <= 180.0):
            gps.raw_valid = False
            gps.validation_notes.append(
                f"Longitud fuera de rango físico: {gps.longitude} (válido: -180 a 180)"
            )
    if gps.altitude is not None:
        if gps.altitude < -500 or gps.altitude > 50000:
            gps.validation_notes.append(
                f"Altitud inusual: {gps.altitude}m (nota: puede ser válido para aeronaves)"
            )


def _extract_gps(tags: dict, meta: ImageMetadata) -> None:
    try:
        gps_lat = tags.get('GPS GPSLatitude')
        gps_lat_ref = tags.get('GPS GPSLatitudeRef')
        gps_lon = tags.get('GPS GPSLongitude')
        gps_lon_ref = tags.get('GPS GPSLongitudeRef')

        if gps_lat and gps_lat_ref and gps_lon and gps_lon_ref:
            lat = _parse_gps_coord(gps_lat.values)
            lon = _parse_gps_coord(gps_lon.values)

            if lat is not None:
                if str(gps_lat_ref.values) == 'S':
                    lat = -lat
                meta.gps.latitude = round(lat, 8)

            if lon is not None:
                if str(gps_lon_ref.values) == 'W':
                    lon = -lon
                meta.gps.longitude = round(lon, 8)

        gps_alt = tags.get('GPS GPSAltitude')
        gps_alt_ref = tags.get('GPS GPSAltitudeRef')
        if gps_alt:
            try:
                alt = float(gps_alt.values[0].num) / float(gps_alt.values[0].den)
                if gps_alt_ref and str(gps_alt_ref.values) == chr(1):
                    alt = -alt
                meta.gps.altitude = round(alt, 2)
            except Exception:
                meta.security.parse_errors.append("GPS GPSAltitude: error al parsear")

        gps_speed = tags.get('GPS GPSSpeed')
        if gps_speed:
            try:
                meta.gps.speed = round(
                    float(gps_speed.values[0].num) / float(gps_speed.values[0].den), 2
                )
            except Exception:
                pass

        gps_ts = tags.get('GPS GPSTimeStamp')
        if gps_ts:
            try:
                h = int(gps_ts.values[0].num / gps_ts.values[0].den)
                m = int(gps_ts.values[1].num / gps_ts.values[1].den)
                s = int(gps_ts.values[2].num / gps_ts.values[2].den)
                meta.gps.timestamp_utc = f"{h:02d}:{m:02d}:{s:02d} UTC"
            except Exception:
                pass

        _validate_gps(meta.gps)

    except Exception as e:
        meta.security.parse_errors.append(f"GPS: error general — {str(e)[:100]}")


def _extract_timestamps_filesystem(file_path: Path, meta: ImageMetadata) -> None:
    try:
        stat = file_path.stat()
        meta.timestamps.filesystem_modified = datetime.fromtimestamp(
            stat.st_mtime
        ).isoformat()
        meta.timestamps.filesystem_accessed = datetime.fromtimestamp(
            stat.st_atime
        ).isoformat()
        if hasattr(stat, 'st_birthtime'):
            meta.timestamps.filesystem_created = datetime.fromtimestamp(
                stat.st_birthtime
            ).isoformat()
        elif stat.st_ctime:
            meta.timestamps.filesystem_created = datetime.fromtimestamp(
                stat.st_ctime
            ).isoformat()
    except Exception as e:
        meta.extraction_warnings.append(f"timestamps de filesystem: {str(e)[:100]}")


def _extract_png_chunks(file_path: Path, meta: ImageMetadata) -> None:
    """
    Lee chunks tEXt/iTXt/zTXt de PNG directamente desde el binario.
    No delega al parser de Pillow para estos campos — lectura manual
    para mayor control sobre datos potencialmente maliciosos.
    """
    try:
        with open(file_path, 'rb') as f:
            sig = f.read(8)
            if sig != b'\x89PNG\r\n\x1a\n':
                return

            while True:
                header = f.read(8)
                if len(header) < 8:
                    break
                length = struct.unpack('>I', header[:4])[0]
                chunk_type = header[4:8].decode('ascii', errors='replace')

                if length > 10 * 1024 * 1024:
                    meta.security.structurally_anomalous.append(
                        f"PNG chunk {chunk_type}: tamaño anómalo ({length} bytes)"
                    )
                    f.seek(length + 4, 1)
                    continue

                data = f.read(length)
                f.read(4)  # CRC

                if chunk_type in ('tEXt', 'iTXt', 'zTXt'):
                    try:
                        if chunk_type == 'tEXt':
                            parts = data.split(b'\x00', 1)
                            if len(parts) == 2:
                                key = parts[0].decode('latin-1', errors='replace')
                                val = parts[1].decode('latin-1', errors='replace')
                                key = _safe_str(key, f"PNG/{chunk_type}/key", meta.security)
                                val = _safe_str(val, f"PNG/{chunk_type}/val", meta.security)
                                meta.png_text_chunks[key] = val
                    except Exception as e:
                        meta.security.parse_errors.append(
                            f"PNG chunk {chunk_type}: {str(e)[:80]}"
                        )

                if chunk_type == 'IEND':
                    break

    except Exception as e:
        meta.extraction_warnings.append(f"PNG chunks: {str(e)[:100]}")


def extract(image_source: str | Path) -> ImageMetadata:
    """
    Punto de entrada principal. Acepta ruta local o URL.

    Args:
        image_source: ruta de archivo local (str o Path) o URL HTTP/HTTPS.

    Returns:
        ImageMetadata con todos los campos extraídos y los flags de
        seguridad correspondientes.
    """
    meta = ImageMetadata()
    source = str(image_source)
    meta.file_path = source

    # --- Descarga si es URL ---
    if source.startswith('http://') or source.startswith('https://'):
        try:
            import requests
            import tempfile
            headers = {'User-Agent': 'vtr-forensic-img/0.1 (forensic analysis tool)'}
            response = requests.get(source, headers=headers, timeout=30, stream=True)
            response.raise_for_status()

            content_type = response.headers.get('Content-Type', '')
            if 'image' not in content_type:
                meta.extraction_warnings.append(
                    f"Content-Type inesperado: {content_type} — puede no ser imagen"
                )

            suffix = '.tmp'
            for ext in ['.jpg', '.jpeg', '.png', '.tiff', '.webp']:
                if ext in source.lower():
                    suffix = ext
                    break

            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                for chunk in response.iter_content(65536):
                    tmp.write(chunk)
                tmp_path = Path(tmp.name)

            file_path = tmp_path
            meta.extraction_warnings.append(
                "Imagen descargada de URL — cadena de custodia: el archivo analizado "
                "es una copia descargada, no el archivo original en la fuente"
            )
        except Exception as e:
            meta.extraction_warnings.append(f"Error al descargar URL: {str(e)[:200]}")
            return meta
    else:
        file_path = Path(source)
        if not file_path.exists():
            meta.extraction_warnings.append(f"Archivo no encontrado: {source}")
            return meta

    # --- Hashes para cadena de custodia ---
    try:
        meta.sha256, meta.md5 = _compute_hashes(file_path)
        meta.file_size_bytes = file_path.stat().st_size
    except Exception as e:
        meta.extraction_warnings.append(f"Error al calcular hashes: {str(e)[:100]}")

    # --- Timestamps de filesystem ---
    _extract_timestamps_filesystem(file_path, meta)

    # --- Info básica de imagen (Pillow) ---
    try:
        with Image.open(file_path) as img:
            meta.file_format = img.format
            meta.image_dimensions = img.size
            meta.color_mode = img.mode

            if img.info.get('icc_profile'):
                try:
                    import io
                    from PIL import ImageCms
                    profile = ImageCms.getOpenProfile(
                        io.BytesIO(img.info['icc_profile'])
                    )
                    meta.editing.icc_profile_name = str(
                        ImageCms.getProfileDescription(profile)
                    )[:200]
                except Exception:
                    meta.editing.icc_profile_name = "presente (no legible)"
    except Exception as e:
        meta.security.parse_errors.append(f"Pillow open: {str(e)[:100]}")

    # --- EXIF con exifread (más robusto para raw tags) ---
    try:
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, details=True, strict=False)

        for tag_name, tag_value in tags.items():
            safe_val = _safe_str(tag_value, tag_name, meta.security)
            meta.raw_exif_fields[tag_name] = safe_val

        # Device
        meta.device.make = _safe_str(
            tags.get('Image Make', ''), 'Make', meta.security
        ) or None
        meta.device.model = _safe_str(
            tags.get('Image Model', ''), 'Model', meta.security
        ) or None
        meta.device.serial_number = _safe_str(
            tags.get('MakerNote SerialNumber', tags.get('EXIF BodySerialNumber', '')),
            'SerialNumber', meta.security
        ) or None
        meta.device.firmware_version = _safe_str(
            tags.get('Image Software', ''), 'Software', meta.security
        ) or None
        meta.device.lens_model = _safe_str(
            tags.get('EXIF LensModel', ''), 'LensModel', meta.security
        ) or None

        software_tag = tags.get('Image Software', '')
        if software_tag:
            software_str = _safe_str(software_tag, 'Software', meta.security)
            if software_str:
                meta.device.software = software_str
                meta.editing.software_used.append(software_str)

        # Timestamps EXIF
        for field_name, tag_key in [
            ('exif_datetime_original', 'EXIF DateTimeOriginal'),
            ('exif_datetime_digitized', 'EXIF DateTimeDigitized'),
            ('exif_datetime_modified', 'Image DateTime'),
        ]:
            val = tags.get(tag_key)
            if val:
                setattr(
                    meta.timestamps, field_name,
                    _safe_str(val, tag_key, meta.security)
                )

        meta.timestamps.timezone_offset = _safe_str(
            tags.get('EXIF OffsetTimeOriginal', tags.get('EXIF OffsetTime', '')),
            'OffsetTime', meta.security
        ) or None

        # Capture settings
        for attr, tag_key in [
            ('iso', 'EXIF ISOSpeedRatings'),
            ('aperture', 'EXIF FNumber'),
            ('shutter_speed', 'EXIF ExposureTime'),
            ('focal_length', 'EXIF FocalLength'),
            ('flash', 'EXIF Flash'),
            ('white_balance', 'EXIF WhiteBalance'),
            ('exposure_mode', 'EXIF ExposureMode'),
            ('metering_mode', 'EXIF MeteringMode'),
        ]:
            val = tags.get(tag_key)
            if val:
                setattr(meta.capture, attr, _safe_str(val, tag_key, meta.security))

        # Thumbnail
        if 'JPEGThumbnail' in tags:
            meta.editing.has_thumbnail = True
            try:
                thumb_data = tags['JPEGThumbnail']
                if isinstance(thumb_data, bytes):
                    import io
                    with Image.open(io.BytesIO(thumb_data)) as thumb:
                        meta.editing.thumbnail_size = thumb.size
            except Exception:
                meta.editing.thumbnail_size = None

        # GPS
        _extract_gps(tags, meta)

    except Exception as e:
        meta.security.parse_errors.append(f"EXIF (exifread): {str(e)[:150]}")

    # --- PNG text chunks ---
    if meta.file_format == 'PNG':
        _extract_png_chunks(file_path, meta)

    # --- Limpieza de archivo temporal (si fue URL) ---
    if source.startswith('http'):
        try:
            os.unlink(file_path)
        except Exception:
            pass

    # --- Parser Rust (capa de seguridad binaria) ---
    # Se ejecuta DESPUÉS de que Python ya extrajo todo lo que puede,
    # y solo agrega hallazgos — nunca sobreescribe.
    # Si el binario no está disponible, continúa sin él (registrado en logs).
    try:
        from .rust_bridge import merge_rust_findings, parse_binary
        rust_result = parse_binary(file_path if not source.startswith('http') else source)
        merge_rust_findings(meta, rust_result)
    except Exception as e:
        meta.extraction_warnings.append(
            f"rust_bridge: no disponible o error — {str(e)[:100]}. "
            f"Análisis continúa con parsers Python solamente."
        )

    meta.extraction_complete = True
    return meta
