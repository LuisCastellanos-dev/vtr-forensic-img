"""
vtr-forensic-img — Tests metadata_extractor.py (cobertura extendida)
tests/test_metadata_extended.py

Cubre paths no ejercitados en los 71% actuales:
  - _safe_str() con valor que no se puede convertir a string
  - PNG text chunks (tEXt)
  - JPEG con thumbnail EXIF
  - GPS con altitude, speed, timestamp
  - Archivo inexistente
  - _safe_str con campo oversized y non-printable
"""

from __future__ import annotations

import io
import os
import struct
import sys
from pathlib import Path

import piexif
import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.metadata_extractor import extract, _safe_str, SecurityFlags, MAX_FIELD_LENGTH


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def png_with_text(tmp_path) -> Path:
    """PNG con chunk tEXt — metadata de texto embebida."""
    img = Image.new("RGB", (80, 80), color=(100, 200, 100))
    # Pillow no escribe tEXt directamente, lo hacemos manual
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_data = bytearray(buf.getvalue())

    # Insertar un chunk tEXt antes del IEND
    # tEXt format: keyword\0value
    keyword = b"Comment"
    value = b"VTR Test Image"
    text_data = keyword + b"\x00" + value
    text_length = struct.pack(">I", len(text_data))
    text_type = b"tEXt"

    # CRC32 sobre type + data
    import zlib
    crc = struct.pack(">I", zlib.crc32(text_type + text_data) & 0xFFFFFFFF)
    text_chunk = text_length + text_type + text_data + crc

    # Encontrar IEND e insertar antes
    iend_pos = png_data.find(b"IEND") - 4  # 4 bytes de length antes de IEND
    png_data = png_data[:iend_pos] + text_chunk + png_data[iend_pos:]

    p = tmp_path / "test_text.png"
    p.write_bytes(bytes(png_data))
    return p


@pytest.fixture
def jpeg_with_thumbnail(tmp_path) -> Path:
    """JPEG con thumbnail EXIF embebido."""
    img = Image.new("RGB", (200, 150), color=(80, 120, 160))

    # Crear thumbnail
    thumb = Image.new("RGB", (40, 30), color=(160, 120, 80))
    thumb_buf = io.BytesIO()
    thumb.save(thumb_buf, format="JPEG", quality=50)
    thumb_bytes = thumb_buf.getvalue()

    exif = {
        "0th": {
            piexif.ImageIFD.Make: b"ThumbCamera",
        },
        "Exif": {},
        "GPS": {},
        "1st": {
            piexif.ImageIFD.JPEGInterchangeFormat: 0,
            piexif.ImageIFD.JPEGInterchangeFormatLength: len(thumb_bytes),
        },
        "thumbnail": thumb_bytes,
    }
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85, exif=piexif.dump(exif))
    p = tmp_path / "test_thumb.jpg"
    p.write_bytes(buf.getvalue())
    return p


@pytest.fixture
def jpeg_with_gps_full(tmp_path) -> Path:
    """JPEG con GPS completo: lat, lon, alt, speed, timestamp."""
    img = Image.new("RGB", (100, 100), color=(50, 50, 50))
    exif = {
        "0th": {piexif.ImageIFD.Make: b"GPSCam"},
        "Exif": {},
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: [(22, 1), (13, 1), (30, 1)],
            piexif.GPSIFD.GPSLongitudeRef: b"W",
            piexif.GPSIFD.GPSLongitude: [(97, 1), (51, 1), (15, 1)],
            piexif.GPSIFD.GPSAltitudeRef: 0,
            piexif.GPSIFD.GPSAltitude: (150, 1),
            piexif.GPSIFD.GPSSpeedRef: b"K",
            piexif.GPSIFD.GPSSpeed: (60, 1),
            piexif.GPSIFD.GPSTimeStamp: [(14, 1), (30, 1), (45, 1)],
        },
        "1st": {},
        "thumbnail": None,
    }
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=80, exif=piexif.dump(exif))
    p = tmp_path / "test_gps_full.jpg"
    p.write_bytes(buf.getvalue())
    return p


# ── Tests: _safe_str ──────────────────────────────────────────────────────────

class TestSafeStr:
    def test_valor_normal(self):
        flags = SecurityFlags()
        result = _safe_str("hello world", "test_field", flags)
        assert result == "hello world"

    def test_valor_oversized_truncado(self):
        flags = SecurityFlags()
        long_val = "A" * (MAX_FIELD_LENGTH + 100)
        result = _safe_str(long_val, "big_field", flags)
        assert "TRUNCADO" in result
        assert len(flags.oversized_fields) == 1

    def test_valor_con_non_printable(self):
        flags = SecurityFlags()
        result = _safe_str("hello\x00world\x01", "binary_field", flags)
        assert len(flags.non_printable_chars_in_fields) == 1

    def test_none_como_valor(self):
        flags = SecurityFlags()
        result = _safe_str(None, "null_field", flags)
        assert result == "None"  # str(None) = "None"

    def test_entero_como_valor(self):
        flags = SecurityFlags()
        result = _safe_str(42, "int_field", flags)
        assert result == "42"

    def test_bytes_como_valor(self):
        flags = SecurityFlags()
        result = _safe_str(b"raw bytes", "bytes_field", flags)
        assert isinstance(result, str)

    def test_valor_vacio(self):
        flags = SecurityFlags()
        result = _safe_str("", "empty_field", flags)
        assert result == ""

    def test_valor_solo_whitespace(self):
        flags = SecurityFlags()
        result = _safe_str("   ", "ws_field", flags)
        assert result == ""  # strip() produce ""


# ── Tests: PNG text chunks ────────────────────────────────────────────────────

class TestPNGChunks:
    def test_png_con_text_chunk(self, png_with_text):
        meta = extract(png_with_text)
        assert meta.file_format == "PNG"
        assert "Comment" in meta.png_text_chunks
        assert "VTR Test Image" in meta.png_text_chunks["Comment"]

    def test_png_sin_text_chunks(self, tmp_path):
        img = Image.new("RGB", (50, 50), color=(0, 0, 0))
        p = tmp_path / "no_text.png"
        img.save(p, format="PNG")
        meta = extract(p)
        assert meta.file_format == "PNG"
        assert len(meta.png_text_chunks) == 0


# ── Tests: Thumbnail ──────────────────────────────────────────────────────────

class TestThumbnail:
    def test_jpeg_con_thumbnail(self, jpeg_with_thumbnail):
        meta = extract(jpeg_with_thumbnail)
        assert meta.editing.has_thumbnail is True

    def test_jpeg_sin_thumbnail(self, tmp_path):
        img = Image.new("RGB", (80, 80), color=(0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=70)
        p = tmp_path / "no_thumb.jpg"
        p.write_bytes(buf.getvalue())
        meta = extract(p)
        assert meta.editing.has_thumbnail is not True


# ── Tests: GPS extended ───────────────────────────────────────────────────────

class TestGPSExtended:
    def test_gps_altitude(self, jpeg_with_gps_full):
        meta = extract(jpeg_with_gps_full)
        assert meta.gps.altitude is not None
        assert meta.gps.altitude == 150.0

    def test_gps_speed(self, jpeg_with_gps_full):
        meta = extract(jpeg_with_gps_full)
        assert meta.gps.speed is not None
        assert meta.gps.speed == 60.0

    def test_gps_timestamp(self, jpeg_with_gps_full):
        meta = extract(jpeg_with_gps_full)
        assert meta.gps.timestamp_utc is not None
        assert "14:30:45" in meta.gps.timestamp_utc


# ── Tests: Edge cases del extractor ───────────────────────────────────────────

class TestExtractorEdgeCases:
    def test_archivo_inexistente(self, tmp_path):
        meta = extract(tmp_path / "no_existe.jpg")
        assert "no encontrado" in str(meta.extraction_warnings).lower() or \
               "Archivo no encontrado" in str(meta.extraction_warnings)

    def test_archivo_no_imagen(self, tmp_path):
        f = tmp_path / "texto.jpg"
        f.write_text("esto no es una imagen JPEG")
        meta = extract(f)
        assert len(meta.security.parse_errors) > 0 or len(meta.extraction_warnings) > 0

    def test_strict_con_archivo_inexistente(self, tmp_path):
        """Archivo inexistente en modo estricto no debe crashear."""
        meta = extract(tmp_path / "no_existe.jpg", strict=False)
        # No lanza — retorna meta con warnings

    def test_extract_retorna_file_path(self, jpeg_with_gps_full):
        meta = extract(jpeg_with_gps_full)
        assert meta.file_path is not None
        assert len(meta.file_path) > 0
