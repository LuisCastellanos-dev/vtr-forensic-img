"""
vtr-forensic-img — Tests v0.2.0
tests/test_v020_modules.py

Cobertura de los cuatro módulos del roadmap v0.2.0:
  1. strict_mode.py — AnalysisContext y StrictModeViolation
  2. entropy_analyzer.py — entropía de Shannon por bloques
  3. signature_verifier.py — verificación Ed25519
  4. diff_analyzer.py — comparación diferencial entre dos imágenes
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import nacl.signing
import piexif
import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.strict_mode import AnalysisContext, StrictModeViolation
from core.entropy_analyzer import analyze as entropy_analyze
from core.signature_verifier import sign_image, verify_signature
from core.diff_analyzer import compare
from core.metadata_extractor import extract


# ─── Fixtures adicionales para v0.2.0 ────────────────────────────────────────

@pytest.fixture
def jpeg_pair_identical(tmp_path) -> tuple[Path, Path]:
    """Dos copias idénticas del mismo JPEG."""
    img = Image.new("RGB", (100, 100), color=(128, 64, 32))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85)
    data = buf.getvalue()
    a = tmp_path / "identical_a.jpg"
    b = tmp_path / "identical_b.jpg"
    a.write_bytes(data)
    b.write_bytes(data)
    return a, b


@pytest.fixture
def jpeg_pair_different(tmp_path) -> tuple[Path, Path]:
    """Dos JPEGs con contenido visual distinto."""
    img_a = Image.new("RGB", (100, 100), color=(128, 64, 32))
    buf_a = io.BytesIO()
    img_a.save(buf_a, format="JPEG", quality=85)
    a = tmp_path / "diff_a.jpg"
    a.write_bytes(buf_a.getvalue())

    img_b = Image.new("RGB", (100, 100), color=(32, 64, 128))
    buf_b = io.BytesIO()
    img_b.save(buf_b, format="JPEG", quality=85)
    b = tmp_path / "diff_b.jpg"
    b.write_bytes(buf_b.getvalue())
    return a, b


@pytest.fixture
def jpeg_pair_metadata_only_diff(tmp_path) -> tuple[Path, Path]:
    """Mismos píxeles, metadata EXIF distinta."""
    img = Image.new("RGB", (80, 80), color=(100, 100, 100))

    exif_a = {
        "0th": {piexif.ImageIFD.Make: b"CameraA", piexif.ImageIFD.Model: b"ModelA"},
        "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None,
    }
    buf_a = io.BytesIO()
    img.save(buf_a, format="JPEG", quality=90, exif=piexif.dump(exif_a))
    a = tmp_path / "meta_a.jpg"
    a.write_bytes(buf_a.getvalue())

    exif_b = {
        "0th": {piexif.ImageIFD.Make: b"CameraB", piexif.ImageIFD.Model: b"ModelB"},
        "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None,
    }
    buf_b = io.BytesIO()
    img.save(buf_b, format="JPEG", quality=90, exif=piexif.dump(exif_b))
    b = tmp_path / "meta_b.jpg"
    b.write_bytes(buf_b.getvalue())
    return a, b


@pytest.fixture
def ed25519_keypair():
    """Par de llaves Ed25519 generadas para testing."""
    sk = nacl.signing.SigningKey.generate()
    return sk.encode(), sk.verify_key.encode()


# ─── 1. STRICT MODE ──────────────────────────────────────────────────────────

class TestStrictMode:
    def test_context_forensic_mode_acumula_errores(self):
        """Modo forense (default): registra errores sin lanzar."""
        ctx = AnalysisContext(strict=False)
        ctx.record_error("GPS", "denominador cero")
        ctx.record_error("EXIF", "campo corrupto")
        assert len(ctx.errors) == 2

    def test_context_strict_mode_lanza_al_primer_error(self):
        """Modo estricto: lanza StrictModeViolation inmediatamente."""
        ctx = AnalysisContext(strict=True)
        with pytest.raises(StrictModeViolation) as exc_info:
            ctx.record_error("GPS", "denominador cero")
        assert exc_info.value.field_name == "GPS"
        assert "denominador cero" in exc_info.value.reason

    def test_strict_violation_incluye_offset(self):
        ctx = AnalysisContext(strict=True)
        with pytest.raises(StrictModeViolation) as exc_info:
            ctx.record_error("JPEG_MARKER", "truncado", byte_offset=0x41D)
        assert exc_info.value.byte_offset == 0x41D
        assert "0x41D" in str(exc_info.value)

    def test_strict_warning_tambien_lanza(self):
        """En modo estricto, los warnings también detienen el análisis."""
        ctx = AnalysisContext(strict=True)
        with pytest.raises(StrictModeViolation):
            ctx.record_warning("timestamps", "no se pudo leer")

    def test_forensic_warning_no_lanza(self):
        ctx = AnalysisContext(strict=False)
        ctx.record_warning("timestamps", "no se pudo leer")
        assert len(ctx.warnings) == 1

    def test_strict_oversized_lanza(self):
        ctx = AnalysisContext(strict=True)
        with pytest.raises(StrictModeViolation) as exc_info:
            ctx.record_oversized("ImageDescription", 3000, 2048)
        assert "3000" in exc_info.value.reason

    def test_strict_non_printable_lanza(self):
        ctx = AnalysisContext(strict=True)
        with pytest.raises(StrictModeViolation):
            ctx.record_non_printable("Comment", 5)

    def test_extract_strict_con_imagen_valida_no_lanza(self, jpeg_clean):
        """Imagen limpia en modo estricto debe completar sin error."""
        meta = extract(jpeg_clean, strict=True)
        assert meta.extraction_complete is True

    def test_extract_strict_con_archivo_vacio_lanza(self, jpeg_zero_bytes):
        """Archivo vacío en modo estricto debe lanzar StrictModeViolation."""
        with pytest.raises(StrictModeViolation):
            extract(jpeg_zero_bytes, strict=True)

    def test_extract_sin_strict_es_default(self, jpeg_clean):
        """Sin parámetro strict, el comportamiento es forense (no lanza)."""
        meta = extract(jpeg_clean)
        assert meta.extraction_complete is True


# ─── 2. ENTROPY ANALYZER ─────────────────────────────────────────────────────

class TestEntropyAnalyzer:
    def test_jpeg_limpio_retorna_resultado_valido(self, jpeg_clean):
        r = entropy_analyze(jpeg_clean)
        assert r.applicable is True
        assert r.global_entropy >= 0.0
        assert r.global_entropy <= 8.0  # máximo teórico de Shannon
        assert r.total_blocks > 0

    def test_entropia_global_en_rango_shannon(self, jpeg_clean):
        """Shannon entropy está entre 0.0 y 8.0 bits/byte — siempre."""
        r = entropy_analyze(jpeg_clean)
        assert 0.0 <= r.global_entropy <= 8.0

    def test_imagen_uniforme_baja_entropia(self, jpeg_clean):
        """Imagen de un solo color tiene entropía muy baja."""
        r = entropy_analyze(jpeg_clean)
        # Una imagen JPEG de un solo color tiene entropía baja
        # pero no 0.0 porque JPEG comprime con artefactos
        assert r.block_std_entropy < 1.0

    def test_parametros_registrados_en_output(self, jpeg_clean):
        """El block_size y threshold usados deben registrarse."""
        r = entropy_analyze(jpeg_clean, block_size=32, std_threshold=3.0)
        assert r.block_size_used == 32
        assert r.std_threshold_used == 3.0

    def test_caveats_siempre_presentes(self, jpeg_clean):
        r = entropy_analyze(jpeg_clean)
        assert len(r.caveats) > 0

    def test_interpretacion_presente(self, jpeg_clean):
        r = entropy_analyze(jpeg_clean)
        assert r.interpretation and len(r.interpretation) > 10

    def test_archivo_vacio_no_aplicable(self, jpeg_zero_bytes):
        r = entropy_analyze(jpeg_zero_bytes)
        assert r.applicable is False
        assert r.skip_reason

    def test_archivo_inexistente_no_aplicable(self, tmp_path):
        r = entropy_analyze(tmp_path / "no_existe.jpg")
        assert r.applicable is False

    def test_reproducibilidad(self, jpeg_clean):
        """Mismo archivo, mismos parámetros → mismo resultado."""
        r1 = entropy_analyze(jpeg_clean, block_size=64, std_threshold=2.0)
        r2 = entropy_analyze(jpeg_clean, block_size=64, std_threshold=2.0)
        assert r1.global_entropy == r2.global_entropy
        assert r1.block_mean_entropy == r2.block_mean_entropy

    def test_umbral_menor_mas_anomalias(self, jpeg_clean):
        """Umbral más bajo debe detectar >= bloques anómalos que uno alto."""
        r_low = entropy_analyze(jpeg_clean, std_threshold=0.5)
        r_high = entropy_analyze(jpeg_clean, std_threshold=5.0)
        assert r_low.anomalous_ratio >= r_high.anomalous_ratio


# ─── 3. SIGNATURE VERIFIER ───────────────────────────────────────────────────

class TestSignatureVerifier:
    def test_roundtrip_firma_y_verifica(self, jpeg_clean, ed25519_keypair):
        """Firmar y verificar con la misma keypair debe dar verified=True."""
        priv, pub = ed25519_keypair
        sig, sha256 = sign_image(jpeg_clean, priv)
        r = verify_signature(jpeg_clean, sig, pub)
        assert r.verified is True
        assert r.image_sha256 == sha256

    def test_firma_con_llave_incorrecta_falla(self, jpeg_clean, ed25519_keypair):
        """Firma válida verificada con llave pública incorrecta → False."""
        priv, _ = ed25519_keypair
        sig, _ = sign_image(jpeg_clean, priv)
        wrong_pub = nacl.signing.SigningKey.generate().verify_key.encode()
        r = verify_signature(jpeg_clean, sig, wrong_pub)
        assert r.verified is False
        assert r.error == "firma inválida"

    def test_imagen_modificada_invalida_firma(self, jpeg_clean, ed25519_keypair, tmp_path):
        """Un solo byte añadido al archivo invalida la firma."""
        priv, pub = ed25519_keypair
        sig, _ = sign_image(jpeg_clean, priv)

        modified = tmp_path / "modified.jpg"
        data = jpeg_clean.read_bytes() + b"\x00"
        modified.write_bytes(data)

        r = verify_signature(modified, sig, pub)
        assert r.verified is False

    def test_firma_longitud_incorrecta(self, jpeg_clean, ed25519_keypair):
        _, pub = ed25519_keypair
        r = verify_signature(jpeg_clean, b"corta", pub)
        assert r.verified is False
        assert "64 bytes" in r.error

    def test_llave_publica_longitud_incorrecta(self, jpeg_clean):
        r = verify_signature(jpeg_clean, b"\x00" * 64, b"corta")
        assert r.verified is False
        assert "32 bytes" in r.error

    def test_archivo_inexistente(self, ed25519_keypair):
        _, pub = ed25519_keypair
        r = verify_signature("/no/existe.jpg", b"\x00" * 64, pub)
        assert r.verified is False
        assert "no encontrado" in r.error

    def test_sign_con_llave_invalida_lanza(self, jpeg_clean):
        with pytest.raises(ValueError):
            sign_image(jpeg_clean, b"llave_muy_corta")

    def test_sign_archivo_inexistente_lanza(self, ed25519_keypair):
        priv, _ = ed25519_keypair
        with pytest.raises(FileNotFoundError):
            sign_image("/no/existe.jpg", priv)

    def test_detail_incluye_nombre_archivo(self, jpeg_clean, ed25519_keypair):
        """El detail del resultado debe incluir el nombre del archivo."""
        priv, pub = ed25519_keypair
        sig, _ = sign_image(jpeg_clean, priv)
        r = verify_signature(jpeg_clean, sig, pub)
        assert "clean.jpg" in r.detail

    def test_hashes_en_resultado(self, jpeg_clean, ed25519_keypair):
        priv, pub = ed25519_keypair
        sig, sha256 = sign_image(jpeg_clean, priv)
        r = verify_signature(jpeg_clean, sig, pub)
        assert r.image_sha256 == sha256
        assert len(r.public_key_hex) == 64  # 32 bytes en hex
        assert len(r.signature_hex) == 128  # 64 bytes en hex


# ─── 4. DIFF ANALYZER ────────────────────────────────────────────────────────

class TestDiffAnalyzer:
    def test_imagenes_identicas(self, jpeg_pair_identical):
        a, b = jpeg_pair_identical
        r = compare(a, b)
        assert r.binary.identical is True
        assert r.binary.sha256_a == r.binary.sha256_b
        assert "IDÉNTICAS" in r.summary or "IDENTICAS" in r.summary

    def test_imagenes_distintas_binario(self, jpeg_pair_different):
        a, b = jpeg_pair_different
        r = compare(a, b)
        assert r.binary.identical is False
        assert r.binary.sha256_a != r.binary.sha256_b
        assert r.binary.first_diff_offset is not None
        assert r.binary.total_diff_bytes > 0

    def test_misma_imagen_consigo_misma(self, jpeg_clean):
        """Comparar una imagen consigo misma → idénticas."""
        r = compare(jpeg_clean, jpeg_clean)
        assert r.binary.identical is True

    def test_metadata_diff_detecta_cambios(self, jpeg_pair_metadata_only_diff):
        """Mismos píxeles, metadata distinta → metadata diff no vacío."""
        a, b = jpeg_pair_metadata_only_diff
        r = compare(a, b)
        assert r.binary.identical is False
        # Debe detectar diferencias en campos de metadata
        assert r.metadata.fields_different > 0 or r.metadata.fields_only_in_a > 0 or r.metadata.fields_only_in_b > 0

    def test_visual_diff_imagenes_distintas(self, jpeg_pair_different):
        a, b = jpeg_pair_different
        r = compare(a, b)
        if r.visual.dimensions_match:
            assert r.visual.diff_pixels > 0
            assert r.visual.diff_ratio > 0.0

    def test_visual_diff_imagenes_identicas(self, jpeg_pair_identical):
        a, b = jpeg_pair_identical
        r = compare(a, b)
        # Binariamente idénticas → no se hace comparación visual (optimización)
        assert r.binary.identical is True

    def test_un_byte_modificado(self, jpeg_clean, tmp_path):
        """Un byte modificado en metadata: SHA distinto, posible 0 píxeles distintos."""
        modified = tmp_path / "mod.jpg"
        data = bytearray(jpeg_clean.read_bytes())
        data[100] = (data[100] + 1) % 256
        modified.write_bytes(bytes(data))

        r = compare(jpeg_clean, modified)
        assert r.binary.identical is False
        assert r.binary.total_diff_bytes >= 1

    def test_archivo_a_inexistente(self, jpeg_clean, tmp_path):
        r = compare(tmp_path / "no_existe.jpg", jpeg_clean)
        assert r.error is not None
        assert "no encontrada" in r.error

    def test_archivo_b_inexistente(self, jpeg_clean, tmp_path):
        r = compare(jpeg_clean, tmp_path / "no_existe.jpg")
        assert r.error is not None
        assert "no encontrada" in r.error

    def test_summary_incluye_sha256(self, jpeg_pair_different):
        a, b = jpeg_pair_different
        r = compare(a, b)
        assert r.binary.sha256_a[:16] in r.summary

    def test_size_difference_calculado(self, jpeg_pair_different):
        a, b = jpeg_pair_different
        r = compare(a, b)
        expected_diff = r.binary.size_b - r.binary.size_a
        assert r.binary.size_difference == expected_diff

    def test_metadata_diff_fields_identical_count(self, jpeg_pair_identical):
        """Imágenes idénticas: no se hace diff de metadata (optimización)."""
        a, b = jpeg_pair_identical
        r = compare(a, b)
        assert r.binary.identical is True
        # Cuando son idénticas, no se calcula metadata diff
        assert r.metadata.fields_different == 0
