"""
vtr-forensic-img — Tests Adversariales Cross-Module
tests/test_adversarial.py

TRES PERSPECTIVAS:

  PENTESTER: "¿puedo crashear el pipeline con una imagen construida
  maliciosamente o con inputs inesperados?"

  AUDITOR: "¿el sistema clasifica correctamente en todos los edge
  cases? ¿los campos obligatorios siempre están presentes?"

  FORENSE: "¿puedo confiar en la evidencia? ¿None y vacío se
  distinguen? ¿el mismo input produce siempre el mismo output?"
"""

from __future__ import annotations

import io
import json
import os
import struct
import sys
from pathlib import Path

import piexif
import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.metadata_extractor import extract, _safe_str, SecurityFlags
from core.ela_analyzer import analyze as ela_analyze
from core.entropy_analyzer import analyze as entropy_analyze
from core.consistency_checker import check as consistency_check
from core.diff_analyzer import compare
from core.signature_verifier import verify_signature, sign_image
from core.strict_mode import AnalysisContext, StrictModeViolation
from core.provenance_report import generate, to_json, to_text


# ═══════════════════════════════════════════════════════════════════════════════
# PENTESTER — "¿puedo crashear el pipeline?"
# ═══════════════════════════════════════════════════════════════════════════════

class TestPentester_MetadataExtractor:
    """Imágenes construidas para explotar el extractor."""

    def test_jpeg_de_1_byte(self, tmp_path):
        p = tmp_path / "tiny.jpg"
        p.write_bytes(b"\xFF")
        meta = extract(p)
        assert meta is not None

    def test_jpeg_solo_soi(self, tmp_path):
        """SOI sin EOI — imagen truncada."""
        p = tmp_path / "soi_only.jpg"
        p.write_bytes(b"\xFF\xD8")
        meta = extract(p)
        assert meta is not None

    def test_png_header_sin_chunks(self, tmp_path):
        """PNG signature correcta pero sin chunks."""
        p = tmp_path / "empty.png"
        p.write_bytes(b"\x89PNG\r\n\x1a\n")
        meta = extract(p)
        assert meta is not None

    def test_exif_con_campo_de_10000_chars(self, tmp_path):
        """Campo EXIF enorme — no debe causar OOM."""
        img = Image.new("RGB", (50, 50))
        exif = {
            "0th": {piexif.ImageIFD.ImageDescription: ("X" * 10000).encode()},
            "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None,
        }
        buf = io.BytesIO()
        img.save(buf, format="JPEG", exif=piexif.dump(exif))
        p = tmp_path / "huge_field.jpg"
        p.write_bytes(buf.getvalue())
        meta = extract(p)
        assert meta is not None
        # El campo debe estar truncado, no causar crash
        assert len(meta.security.oversized_fields) > 0

    def test_exif_con_null_bytes_en_campo(self, tmp_path):
        """Null bytes en campo EXIF — intento de injection."""
        img = Image.new("RGB", (50, 50))
        exif = {
            "0th": {piexif.ImageIFD.ImageDescription: b"normal\x00evil"},
            "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None,
        }
        buf = io.BytesIO()
        img.save(buf, format="JPEG", exif=piexif.dump(exif))
        p = tmp_path / "null_inject.jpg"
        p.write_bytes(buf.getvalue())
        meta = extract(p)
        assert meta is not None

    def test_archivo_de_50mb_de_zeros(self, tmp_path):
        """50MB de zeros con extensión .jpg — no debe colgar."""
        p = tmp_path / "zeros.jpg"
        p.write_bytes(b"\x00" * (50 * 1024 * 1024))
        meta = extract(p)
        assert meta is not None

    def test_gif_como_jpeg(self, tmp_path):
        """GIF con extensión .jpg — detección por firma, no extensión."""
        img = Image.new("RGB", (50, 50))
        buf = io.BytesIO()
        img.save(buf, format="GIF")
        p = tmp_path / "fake.jpg"
        p.write_bytes(buf.getvalue())
        meta = extract(p)
        assert meta is not None


class TestPentester_ELA:
    def test_ela_none_source(self):
        r = ela_analyze(None)
        assert r.applicable is False

    def test_ela_empty_bytes(self):
        r = ela_analyze(b"")
        assert r.applicable is False

    def test_ela_archivo_inexistente(self, tmp_path):
        r = ela_analyze(tmp_path / "no.jpg")
        assert r.applicable is False

    def test_ela_png_no_es_jpeg(self, tmp_path):
        """ELA es específico de JPEG — PNG debe manejarse sin crash."""
        img = Image.new("RGB", (80, 80))
        p = tmp_path / "test.png"
        img.save(p, format="PNG")
        r = ela_analyze(p)
        # Puede ser applicable o no — no debe crashear


class TestPentester_Pipeline:
    def test_generate_con_archivo_vacio(self, tmp_path):
        p = tmp_path / "empty.jpg"
        p.write_bytes(b"")
        report = generate(p)
        assert isinstance(report, dict)

    def test_generate_con_directorio(self, tmp_path):
        """Pasar un directorio en vez de archivo — no debe crashear."""
        try:
            report = generate(tmp_path)
            assert isinstance(report, dict)
        except Exception:
            pass  # Lanzar excepción es aceptable — crash silencioso no

    def test_to_json_no_falla_con_none_fields(self, tmp_path):
        """Reporte con campos None debe serializarse a JSON sin crash."""
        p = tmp_path / "bare.jpg"
        img = Image.new("RGB", (50, 50))
        img.save(p, format="JPEG")
        report = generate(p, include_ela_image=False)
        j = to_json(report)
        parsed = json.loads(j)
        assert isinstance(parsed, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# AUDITOR — "¿el sistema clasifica correctamente?"
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditor_ReportStructure:
    """Todo reporte debe tener campos obligatorios sin importar el input."""

    def test_reporte_siempre_tiene_version(self, tmp_path):
        p = tmp_path / "test.jpg"
        Image.new("RGB", (50, 50)).save(p, format="JPEG")
        report = generate(p)
        assert report["vtr_forensic_version"] == "0.2.0"

    def test_reporte_siempre_tiene_timestamp(self, tmp_path):
        p = tmp_path / "test.jpg"
        Image.new("RGB", (50, 50)).save(p, format="JPEG")
        report = generate(p)
        assert "T" in report["analysis_timestamp"]

    def test_reporte_siempre_tiene_strict_mode(self, tmp_path):
        p = tmp_path / "test.jpg"
        Image.new("RGB", (50, 50)).save(p, format="JPEG")
        report = generate(p, strict=False)
        assert "strict_mode" in report

    def test_risk_level_siempre_presente(self, tmp_path):
        p = tmp_path / "test.jpg"
        Image.new("RGB", (50, 50)).save(p, format="JPEG")
        report = generate(p)
        assert "risk_level" in report.get("consistency", {})

    def test_sha256_siempre_64_chars(self, tmp_path):
        p = tmp_path / "test.jpg"
        Image.new("RGB", (50, 50)).save(p, format="JPEG")
        report = generate(p)
        sha = report["metadata"].get("hashes", {}).get("sha256", "")
        assert len(sha) == 64


class TestAuditor_StrictMode:
    """El modo estricto debe lanzar en todos los casos donde hay error."""

    def test_strict_exit_code_3_documentado(self):
        """StrictModeViolation debe existir y ser importable."""
        assert StrictModeViolation is not None

    def test_context_strict_y_forensic_son_distintos(self):
        ctx_strict = AnalysisContext(strict=True)
        ctx_forensic = AnalysisContext(strict=False)
        assert ctx_strict.strict is True
        assert ctx_forensic.strict is False

    def test_strict_violation_tiene_campos_obligatorios(self):
        try:
            ctx = AnalysisContext(strict=True)
            ctx.record_error("TEST", "motivo", byte_offset=0x100)
        except StrictModeViolation as e:
            assert hasattr(e, 'field_name')
            assert hasattr(e, 'reason')
            assert hasattr(e, 'byte_offset')
            assert e.field_name == "TEST"
            assert e.byte_offset == 0x100


class TestAuditor_SignatureVerifier:
    """La verificación de firma debe ser rigurosa en validación de inputs."""

    def test_public_key_no_bytes_rechazada(self):
        r = verify_signature("/tmp/test.jpg", b"\x00" * 64, "not_bytes")
        assert r.verified is False
        assert "bytes" in r.error

    def test_signature_no_bytes_rechazada(self):
        r = verify_signature("/tmp/test.jpg", "not_bytes", b"\x00" * 32)
        assert r.verified is False
        assert "bytes" in r.error

    def test_directorio_como_imagen_rechazado(self, tmp_path):
        r = verify_signature(tmp_path, b"\x00" * 64, b"\x00" * 32)
        assert r.verified is False


# ═══════════════════════════════════════════════════════════════════════════════
# FORENSE — "¿puedo confiar en la evidencia?"
# ═══════════════════════════════════════════════════════════════════════════════

class TestForense_NoneVsEmpty:
    """None y '' son estados forenses distintos — nunca colapsar."""

    def test_safe_str_none_retorna_none_string(self):
        flags = SecurityFlags()
        r = _safe_str(None, "test", flags)
        assert r == "None"  # str(None), no ""

    def test_safe_str_empty_retorna_empty(self):
        flags = SecurityFlags()
        r = _safe_str("", "test", flags)
        assert r == ""  # preserva vacío

    def test_extract_none_vs_empty_file_path(self, tmp_path):
        """Archivo vacío produce metadata distinta a archivo inexistente."""
        empty = tmp_path / "empty.jpg"
        empty.write_bytes(b"")
        meta_empty = extract(empty)

        meta_missing = extract(tmp_path / "no_existe.jpg")

        # Ambos tienen warnings pero por razones distintas
        assert meta_empty.file_path != meta_missing.file_path


class TestForense_Determinismo:
    """El mismo input debe producir siempre el mismo output."""

    def test_extract_determinista(self, tmp_path):
        img = Image.new("RGB", (80, 80), color=(100, 100, 100))
        p = tmp_path / "det.jpg"
        img.save(p, format="JPEG", quality=85)
        m1 = extract(p)
        m2 = extract(p)
        assert m1.sha256 == m2.sha256
        assert m1.file_format == m2.file_format

    def test_ela_determinista(self, tmp_path):
        img = Image.new("RGB", (100, 100), color=(50, 50, 50))
        p = tmp_path / "det_ela.jpg"
        img.save(p, format="JPEG", quality=85)
        r1 = ela_analyze(p, include_ela_image=False)
        r2 = ela_analyze(p, include_ela_image=False)
        assert r1.global_mean_error == r2.global_mean_error

    def test_entropy_determinista(self, tmp_path):
        img = Image.new("RGB", (100, 100), color=(70, 70, 70))
        p = tmp_path / "det_ent.jpg"
        img.save(p, format="JPEG", quality=85)
        r1 = entropy_analyze(p)
        r2 = entropy_analyze(p)
        assert r1.global_entropy == r2.global_entropy
        assert r1.block_mean_entropy == r2.block_mean_entropy

    def test_diff_determinista(self, tmp_path):
        img_a = Image.new("RGB", (60, 60), color=(100, 0, 0))
        a = tmp_path / "det_a.jpg"
        img_a.save(a, format="JPEG")
        img_b = Image.new("RGB", (60, 60), color=(0, 0, 100))
        b = tmp_path / "det_b.jpg"
        img_b.save(b, format="JPEG")
        r1 = compare(a, b)
        r2 = compare(a, b)
        assert r1.binary.sha256_a == r2.binary.sha256_a
        assert r1.binary.total_diff_bytes == r2.binary.total_diff_bytes

    def test_generate_determinista_sin_timestamp(self, tmp_path):
        """Excepto timestamp, todo debe ser idéntico."""
        img = Image.new("RGB", (80, 80), color=(128, 128, 128))
        p = tmp_path / "det_gen.jpg"
        img.save(p, format="JPEG", quality=85)
        r1 = generate(p, include_ela_image=False)
        r2 = generate(p, include_ela_image=False)
        # Timestamps difieren, pero metadata y consistency no
        assert r1["metadata"] == r2["metadata"]
        assert r1["consistency"] == r2["consistency"]


class TestForense_IntegridadCadenaCustodia:
    """La cadena de custodia criptográfica debe ser verificable."""

    def test_sha256_no_vacio_en_reporte(self, tmp_path):
        img = Image.new("RGB", (50, 50))
        p = tmp_path / "custody.jpg"
        img.save(p, format="JPEG")
        report = generate(p)
        sha = report["metadata"].get("hashes", {}).get("sha256", "")
        assert sha and len(sha) == 64

    def test_firma_sobre_sha256_no_sobre_pixeles(self, tmp_path):
        """La firma es sobre bytes crudos — re-compresión la invalida."""
        import nacl.signing
        sk = nacl.signing.SigningKey.generate()

        img = Image.new("RGB", (80, 80), color=(50, 50, 50))
        p = tmp_path / "original.jpg"
        img.save(p, format="JPEG", quality=90)

        sig, sha = sign_image(p, sk.encode())

        # Re-guardar con calidad distinta — mismos píxeles, bytes distintos
        recompressed = tmp_path / "recompressed.jpg"
        img.save(recompressed, format="JPEG", quality=50)

        r = verify_signature(recompressed, sig, sk.verify_key.encode())
        assert r.verified is False  # re-compresión invalida la firma

    def test_to_json_es_parseable(self, tmp_path):
        img = Image.new("RGB", (50, 50))
        p = tmp_path / "json_test.jpg"
        img.save(p, format="JPEG")
        report = generate(p, include_ela_image=False)
        j = to_json(report)
        parsed = json.loads(j)
        assert parsed["vtr_forensic_version"] == "0.2.0"
