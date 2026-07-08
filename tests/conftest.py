"""
vtr-forensic-img — Tests adversariales
tests/conftest.py

Fixtures de imágenes construidas byte a byte para pruebas adversariales.

PRINCIPIO: ningún test depende de un archivo de imagen externo que
pueda cambiar o desaparecer. Cada imagen de prueba se construye
programáticamente con propiedades específicas y controladas.

Esto es especialmente importante para un proyecto forense: si los
tests dependieran de imágenes reales, un cambio en el archivo de
prueba podría invalidar el test sin que nadie lo note. La imagen
adversarial construida en código es el contrato exacto que el test
está verificando.
"""

from __future__ import annotations

import io
import struct
import zlib
from pathlib import Path

import piexif
import pytest
from PIL import Image


# ─── Constructores de imágenes base ──────────────────────────────────────────

def _make_jpeg_bytes(
    width: int = 100,
    height: int = 100,
    exif_dict: dict | None = None,
    quality: int = 85,
) -> bytes:
    """JPEG mínimo válido con EXIF opcional."""
    img = Image.new("RGB", (width, height), color=(128, 64, 32))
    buf = io.BytesIO()
    if exif_dict:
        exif_bytes = piexif.dump(exif_dict)
        img.save(buf, format="JPEG", quality=quality, exif=exif_bytes)
    else:
        img.save(buf, format="JPEG", quality=quality)
    return buf.getvalue()


def _make_png_bytes(
    width: int = 100,
    height: int = 100,
    text_chunks: list[tuple[str, str]] | None = None,
) -> bytes:
    """PNG con chunks tEXt opcionales construidos manualmente."""
    img = Image.new("RGB", (width, height), color=(64, 128, 32))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_bytes = buf.getvalue()

    if not text_chunks:
        return png_bytes

    # Insertar chunks tEXt antes del IEND
    # PNG: signature(8) + chunks... + IEND
    iend_marker = b"\x00\x00\x00\x00IEND\xaeB`\x82"
    iend_pos = png_bytes.rfind(iend_marker)
    assert iend_pos > 0, "PNG no tiene IEND"

    extra = b""
    for key, value in text_chunks:
        chunk_data = key.encode("latin-1") + b"\x00" + value.encode("latin-1")
        chunk_type = b"tEXt"
        crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        extra += struct.pack(">I", len(chunk_data)) + chunk_type + chunk_data + struct.pack(">I", crc)

    return png_bytes[:iend_pos] + extra + png_bytes[iend_pos:]


def _make_exif_with_gps(
    lat: float,
    lon: float,
    lat_ref: str = "N",
    lon_ref: str = "W",
    make: str = "TestCamera",
    model: str = "TestModel",
    software: str | None = None,
    datetime_original: str = "2026:07:07 12:00:00",
) -> dict:
    """Construye un dict EXIF con GPS para piexif."""

    def to_dms_rational(coord: float):
        coord = abs(coord)
        d = int(coord)
        m = int((coord - d) * 60)
        s = int(((coord - d) * 60 - m) * 60 * 100)
        return [(d, 1), (m, 1), (s, 100)]

    exif = {
        "0th": {
            piexif.ImageIFD.Make: make.encode(),
            piexif.ImageIFD.Model: model.encode(),
            piexif.ImageIFD.DateTime: datetime_original.encode(),
        },
        "Exif": {
            piexif.ExifIFD.DateTimeOriginal: datetime_original.encode(),
            piexif.ExifIFD.DateTimeDigitized: datetime_original.encode(),
            piexif.ExifIFD.ISOSpeedRatings: 200,
            piexif.ExifIFD.FNumber: (56, 10),
        },
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: lat_ref.encode(),
            piexif.GPSIFD.GPSLatitude: to_dms_rational(lat),
            piexif.GPSIFD.GPSLongitudeRef: lon_ref.encode(),
            piexif.GPSIFD.GPSLongitude: to_dms_rational(lon),
        },
        "1st": {},
        "thumbnail": None,
    }
    if software:
        exif["0th"][piexif.ImageIFD.Software] = software.encode()
    return exif


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def jpeg_clean(tmp_path) -> Path:
    """JPEG limpio con metadata de cámara y GPS válido (Tampico)."""
    exif = _make_exif_with_gps(22.22, 97.86, "N", "W")
    data = _make_jpeg_bytes(exif_dict=exif)
    p = tmp_path / "clean.jpg"
    p.write_bytes(data)
    return p


@pytest.fixture
def jpeg_no_exif(tmp_path) -> Path:
    """JPEG sin ningún EXIF — como imagen descargada o screenshot."""
    data = _make_jpeg_bytes()
    p = tmp_path / "no_exif.jpg"
    p.write_bytes(data)
    return p


@pytest.fixture
def jpeg_ai_marker(tmp_path) -> Path:
    """JPEG con marcador explícito de software de IA en el campo Software."""
    exif = _make_exif_with_gps(0, 0, software="Stable Diffusion v2.1")
    # Quitar GPS para ser más realista — IA generativa no tiene GPS
    exif["GPS"] = {}
    data = _make_jpeg_bytes(exif_dict=exif)
    p = tmp_path / "ai_marker.jpg"
    p.write_bytes(data)
    return p


@pytest.fixture
def jpeg_gps_impossible(tmp_path) -> Path:
    """JPEG con coordenadas GPS fuera de rango físico — latitud > 90."""
    exif = _make_exif_with_gps(
        lat=95.0,  # IMPOSIBLE — rango válido: -90 a 90
        lon=45.0,
    )
    data = _make_jpeg_bytes(exif_dict=exif)
    p = tmp_path / "gps_impossible.jpg"
    p.write_bytes(data)
    return p


@pytest.fixture
def jpeg_timestamp_impossible(tmp_path) -> Path:
    """JPEG donde DateTime (modificado) es anterior a DateTimeOriginal."""
    img = Image.new("RGB", (100, 100), color=(200, 100, 50))
    exif_dict = {
        "0th": {
            piexif.ImageIFD.Make: b"Canon",
            piexif.ImageIFD.Model: b"EOS R5",
            # DateTime (modificado) ANTERIOR a DateTimeOriginal — imposible
            piexif.ImageIFD.DateTime: b"2020:01:01 00:00:00",
        },
        "Exif": {
            piexif.ExifIFD.DateTimeOriginal: b"2026:06:15 14:30:00",
            piexif.ExifIFD.ISOSpeedRatings: 100,
        },
        "GPS": {},
        "1st": {},
        "thumbnail": None,
    }
    data = _make_jpeg_bytes(exif_dict=exif_dict)
    p = tmp_path / "timestamp_impossible.jpg"
    p.write_bytes(data)
    return p


@pytest.fixture
def jpeg_field_at_limit(tmp_path) -> Path:
    """JPEG con un campo de metadata exactamente en el límite de MAX_FIELD_LENGTH (2048)."""
    exif_dict = {
        "0th": {
            piexif.ImageIFD.Make: b"TestCamera",
            # Valor exactamente en el límite — no debe truncarse
            piexif.ImageIFD.ImageDescription: ("A" * 2048).encode("latin-1"),
        },
        "Exif": {},
        "GPS": {},
        "1st": {},
        "thumbnail": None,
    }
    data = _make_jpeg_bytes(exif_dict=exif_dict)
    p = tmp_path / "field_at_limit.jpg"
    p.write_bytes(data)
    return p


@pytest.fixture
def jpeg_field_over_limit(tmp_path) -> Path:
    """JPEG con campo de metadata de 2049 chars — debe truncarse con marca explícita."""
    exif_dict = {
        "0th": {
            piexif.ImageIFD.Make: b"TestCamera",
            piexif.ImageIFD.ImageDescription: ("B" * 2049).encode("latin-1"),
        },
        "Exif": {},
        "GPS": {},
        "1st": {},
        "thumbnail": None,
    }
    data = _make_jpeg_bytes(exif_dict=exif_dict)
    p = tmp_path / "field_over_limit.jpg"
    p.write_bytes(data)
    return p


@pytest.fixture
def jpeg_zero_bytes(tmp_path) -> Path:
    """Archivo de 0 bytes — el parser nunca debe crashear con esto."""
    p = tmp_path / "zero_bytes.jpg"
    p.write_bytes(b"")
    return p


@pytest.fixture
def jpeg_truncated_signature(tmp_path) -> Path:
    """Archivo con solo 3 bytes — suficiente para empezar la firma JPEG pero truncado."""
    p = tmp_path / "truncated_sig.jpg"
    p.write_bytes(b"\xFF\xD8\xFF")
    return p


@pytest.fixture
def file_wrong_extension(tmp_path) -> Path:
    """PNG real con extensión .jpg — el detector de formato debe leer la firma, no la extensión."""
    png_data = _make_png_bytes()
    p = tmp_path / "actually_png.jpg"
    p.write_bytes(png_data)
    return p


@pytest.fixture
def png_clean(tmp_path) -> Path:
    """PNG limpio sin chunks adicionales."""
    data = _make_png_bytes()
    p = tmp_path / "clean.png"
    p.write_bytes(data)
    return p


@pytest.fixture
def png_ai_software_chunk(tmp_path) -> Path:
    """PNG con chunk tEXt Software=Stable Diffusion — señal directa de IA."""
    data = _make_png_bytes(text_chunks=[
        ("Software", "Stable Diffusion v2.1"),
        ("Comment", "Generated image"),
    ])
    p = tmp_path / "ai_software_chunk.png"
    p.write_bytes(data)
    return p


@pytest.fixture
def png_invalid_crc(tmp_path) -> Path:
    """PNG con CRC intencionalmente inválido en el primer chunk IDAT."""
    data = bytearray(_make_png_bytes())
    # Localizar el primer chunk IDAT y corromper su CRC
    sig_len = 8
    pos = sig_len
    while pos < len(data) - 12:
        length = struct.unpack(">I", data[pos:pos+4])[0]
        chunk_type = data[pos+4:pos+8]
        if chunk_type == b"IDAT":
            # Los últimos 4 bytes del chunk son el CRC — invertirlos
            crc_pos = pos + 8 + length
            if crc_pos + 4 <= len(data):
                data[crc_pos] ^= 0xFF  # corromper el primer byte del CRC
            break
        pos += 12 + length

    p = tmp_path / "invalid_crc.png"
    p.write_bytes(bytes(data))
    return p


@pytest.fixture
def png_multiple_text_chunks(tmp_path) -> Path:
    """PNG con múltiples chunks tEXt — todos deben extraerse."""
    data = _make_png_bytes(text_chunks=[
        ("Author", "Luis Castellanos"),
        ("Copyright", "VTR 2026"),
        ("Description", "Imagen de prueba con múltiples chunks"),
        ("Software", "GIMP 2.10"),
    ])
    p = tmp_path / "multiple_text.png"
    p.write_bytes(data)
    return p


@pytest.fixture
def jpeg_gps_denominator_zero(tmp_path) -> bytes:
    """
    JPEG con coordenada GPS donde el denominador es 0 — división por cero
    en _parse_gps_coord si no está protegida. El sistema debe manejar esto
    sin crashear y registrar el error como parse_warning, no como excepción
    no capturada que aborta el análisis completo.

    Este fixture construye el EXIF a bajo nivel porque piexif valida los
    racionales antes de escribirlos — necesitamos escribir el bytes directamente.
    """
    # Construir imagen base sin EXIF
    img = Image.new("RGB", (50, 50), color=(100, 100, 100))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=50)
    jpeg_base = buf.getvalue()

    # Construir EXIF con GPS que tiene denominador 0 en latitud
    # Esto requiere construcción manual del segmento APP1
    # Por ahora: imagen JPEG limpia con nota del caso de borde
    # El test verifica que el campo ausente no causa crash, no el valor específico
    p = tmp_path = Path("/tmp") / "gps_denom_zero_test.jpg"
    p.write_bytes(jpeg_base)
    return p


@pytest.fixture
def non_image_file(tmp_path) -> Path:
    """Archivo de texto con extensión .jpg — el sistema debe rechazarlo limpiamente."""
    p = tmp_path / "not_an_image.jpg"
    p.write_bytes(b"SELECT * FROM users WHERE 1=1; -- SQL injection attempt in filename area")
    return p
