"""
vtr-forensic-img — Tests de integración del pipeline
tests/test_pipeline_integration.py

Cobertura de:
  - core/provenance_report.py (0% → objetivo 80%+)
  - Pipeline completo generate() → to_text() → to_json()
  - Integración entropía en el reporte
  - Edge cases de diff_analyzer no cubiertos
  - Edge cases de entropy_analyzer no cubiertos

PRINCIPIO: estos tests verifican que el pipeline ENSAMBLADO produce
output correcto — no solo que cada módulo individual funciona.
Un módulo puede pasar sus tests unitarios y fallar cuando se conecta
con los demás (ej: provenance_report espera un campo que
metadata_extractor no produce en ciertos edge cases).
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import piexif
import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.provenance_report import generate, to_json, to_text


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def jpeg_with_gps(tmp_path) -> Path:
    """JPEG con metadata completa para pipeline integration."""
    img = Image.new("RGB", (200, 150), color=(100, 80, 60))
    exif = {
        "0th": {
            piexif.ImageIFD.Make: b"IntegrationCamera",
            piexif.ImageIFD.Model: b"Pipeline-Test-v1",
            piexif.ImageIFD.Software: b"VTR Test",
            piexif.ImageIFD.DateTime: b"2026:07:14 10:00:00",
        },
        "Exif": {
            piexif.ExifIFD.DateTimeOriginal: b"2026:07:14 10:00:00",
            piexif.ExifIFD.ISOSpeedRatings: 400,
            piexif.ExifIFD.FNumber: (28, 10),
            piexif.ExifIFD.ExposureTime: (1, 250),
        },
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: [(22, 1), (13, 1), (0, 1)],
            piexif.GPSIFD.GPSLongitudeRef: b"W",
            piexif.GPSIFD.GPSLongitude: [(97, 1), (51, 1), (0, 1)],
        },
        "1st": {},
        "thumbnail": None,
    }
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85, exif=piexif.dump(exif))
    p = tmp_path / "integration_gps.jpg"
    p.write_bytes(buf.getvalue())
    return p


@pytest.fixture
def jpeg_bare(tmp_path) -> Path:
    """JPEG sin EXIF — mínimo."""
    img = Image.new("RGB", (80, 80), color=(200, 200, 200))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=70)
    p = tmp_path / "bare.jpg"
    p.write_bytes(buf.getvalue())
    return p


@pytest.fixture
def jpeg_pair(tmp_path) -> tuple[Path, Path]:
    """Par de JPEGs distintos para diff."""
    img_a = Image.new("RGB", (60, 60), color=(100, 0, 0))
    buf_a = io.BytesIO()
    img_a.save(buf_a, format="JPEG", quality=80)
    a = tmp_path / "pair_a.jpg"
    a.write_bytes(buf_a.getvalue())

    img_b = Image.new("RGB", (60, 60), color=(0, 0, 100))
    buf_b = io.BytesIO()
    img_b.save(buf_b, format="JPEG", quality=80)
    b = tmp_path / "pair_b.jpg"
    b.write_bytes(buf_b.getvalue())
    return a, b


@pytest.fixture
def jpeg_diff_dimensions(tmp_path) -> tuple[Path, Path]:
    """Par de JPEGs con dimensiones distintas."""
    img_a = Image.new("RGB", (100, 100), color=(50, 50, 50))
    buf_a = io.BytesIO()
    img_a.save(buf_a, format="JPEG", quality=80)
    a = tmp_path / "dim_a.jpg"
    a.write_bytes(buf_a.getvalue())

    img_b = Image.new("RGB", (200, 150), color=(50, 50, 50))
    buf_b = io.BytesIO()
    img_b.save(buf_b, format="JPEG", quality=80)
    b = tmp_path / "dim_b.jpg"
    b.write_bytes(buf_b.getvalue())
    return a, b


# ── Tests: provenance_report.generate() ───────────────────────────────────────

class TestProvenanceReportGenerate:
    def test_generate_retorna_dict(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        assert isinstance(report, dict)

    def test_report_tiene_campos_obligatorios(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        assert "vtr_forensic_version" in report
        assert "analysis_timestamp" in report
        assert "image_source" in report
        assert "metadata" in report
        assert "ela" in report
        assert "consistency" in report
        assert "entropy" in report

    def test_version_es_020(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        assert report["vtr_forensic_version"] == "0.2.0"

    def test_timestamp_es_iso(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        ts = report["analysis_timestamp"]
        assert "T" in ts
        assert ts.endswith("+00:00") or ts.endswith("Z")

    def test_metadata_tiene_sha256(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        meta = report["metadata"]
        # SHA-256 debe estar en hashes (consolidado)
        hashes = meta.get("hashes", {})
        assert hashes.get("sha256") and len(hashes["sha256"]) == 64

    def test_ela_presente_en_reporte(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        ela = report["ela"]
        assert "applicable" in ela

    def test_entropy_presente_en_reporte(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        entropy = report["entropy"]
        assert "applicable" in entropy
        assert "global_entropy" in entropy

    def test_consistency_tiene_risk_level(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        c = report["consistency"]
        assert "risk_level" in c

    def test_strict_mode_en_reporte(self, jpeg_with_gps):
        report = generate(jpeg_with_gps, strict=False)
        assert report["strict_mode"] is False

    def test_generate_sin_ela(self, jpeg_with_gps):
        """generate con include_ela_image=False no debe crashear."""
        report = generate(jpeg_with_gps, include_ela_image=False)
        assert report["ela_image_b64"] is None

    def test_generate_con_imagen_sin_exif(self, jpeg_bare):
        """Imagen sin EXIF debe producir reporte completo sin crash."""
        report = generate(jpeg_bare)
        assert isinstance(report, dict)
        assert report["metadata"]["file_format"] == "JPEG"


# ── Tests: to_text() ──────────────────────────────────────────────────────────

class TestToText:
    def test_to_text_retorna_string(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        text = to_text(report)
        assert isinstance(text, str)
        assert len(text) > 100

    def test_to_text_incluye_header(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        text = to_text(report)
        assert "VTR FORENSIC" in text

    def test_to_text_incluye_sha256(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        text = to_text(report)
        sha = report["metadata"].get("hashes", {}).get("sha256", "")
        if sha:
            assert sha[:16] in text

    def test_to_text_incluye_dispositivo(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        text = to_text(report)
        assert "IntegrationCamera" in text

    def test_to_text_incluye_gps(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        text = to_text(report)
        assert "GPS" in text

    def test_to_text_incluye_ela(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        text = to_text(report)
        assert "ELA" in text or "Error Level" in text

    def test_to_text_incluye_entropia(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        text = to_text(report)
        assert "SHANNON" in text.upper() or "ENTROP" in text.upper()

    def test_to_text_incluye_nivel_riesgo(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        text = to_text(report)
        assert "Nivel de riesgo" in text

    def test_to_text_imagen_sin_exif(self, jpeg_bare):
        report = generate(jpeg_bare)
        text = to_text(report)
        assert "No encontrado" in text or "None" in text


# ── Tests: to_json() ──────────────────────────────────────────────────────────

class TestToJson:
    def test_to_json_es_json_valido(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        j = to_json(report)
        parsed = json.loads(j)
        assert isinstance(parsed, dict)

    def test_to_json_roundtrip(self, jpeg_with_gps):
        report = generate(jpeg_with_gps)
        j = to_json(report)
        parsed = json.loads(j)
        assert parsed["vtr_forensic_version"] == "0.2.0"
        assert "metadata" in parsed
        assert "entropy" in parsed


# ── Tests: diff edge cases ────────────────────────────────────────────────────

class TestDiffEdgeCases:
    def test_diff_dimensiones_distintas(self, jpeg_diff_dimensions):
        """Imágenes con dimensiones distintas: visual diff debe reportar skip."""
        from core.diff_analyzer import compare
        a, b = jpeg_diff_dimensions
        r = compare(a, b)
        assert r.binary.identical is False
        assert r.visual.dimensions_match is False
        assert r.visual.skip_reason  # debe explicar por qué no compara píxeles

    def test_diff_summary_siempre_presente(self, jpeg_pair):
        from core.diff_analyzer import compare
        a, b = jpeg_pair
        r = compare(a, b)
        assert r.summary and len(r.summary) > 10

    def test_diff_identicas_no_hace_metadata(self, jpeg_bare):
        """Misma imagen → no calcula metadata diff (optimización)."""
        from core.diff_analyzer import compare
        r = compare(jpeg_bare, jpeg_bare)
        assert r.binary.identical is True
        assert r.metadata.fields_different == 0


# ── Tests: entropy edge cases ─────────────────────────────────────────────────

class TestEntropyEdgeCases:
    def test_imagen_grande_uniforme(self, tmp_path):
        """Imagen grande y uniforme: entropía baja, sin anomalías."""
        from core.entropy_analyzer import analyze
        img = Image.new("RGB", (500, 500), color=(128, 128, 128))
        p = tmp_path / "uniform_large.jpg"
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=95)
        p.write_bytes(buf.getvalue())
        r = analyze(p)
        assert r.applicable is True
        assert r.block_std_entropy < 1.0

    def test_imagen_pequena_para_bloque(self, tmp_path):
        """Imagen más pequeña que el bloque: debe reportar no aplicable o 0 bloques."""
        from core.entropy_analyzer import analyze
        img = Image.new("RGB", (30, 30), color=(100, 100, 100))
        p = tmp_path / "tiny.jpg"
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=50)
        p.write_bytes(buf.getvalue())
        r = analyze(p, block_size=64)
        # Con imagen 30x30 y bloque 64, no hay bloques completos
        assert r.applicable is False or r.total_blocks == 0

    def test_bytes_como_input(self):
        """Pasar bytes directamente en vez de path."""
        from core.entropy_analyzer import analyze
        img = Image.new("RGB", (100, 100), color=(50, 100, 150))
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=80)
        r = analyze(buf.getvalue())
        assert r.applicable is True
        assert r.global_entropy > 0
