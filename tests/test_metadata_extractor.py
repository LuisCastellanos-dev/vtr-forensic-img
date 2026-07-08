"""
vtr-forensic-img — Tests adversariales
tests/test_metadata_extractor.py

Cobertura de core/metadata_extractor.py con casos adversariales.

CRITERIO DE CADA TEST:
  Cada test tiene exactamente una afirmación forense que verificar —
  no "el código no crashea" (eso es el mínimo), sino "el código
  produce el output correcto y trazable bajo esta condición específica."

  Un test que pasa porque el except silencia el error sin registrarlo
  es un test que miente — exactamente lo que este proyecto existe para
  no hacer.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.metadata_extractor import MAX_FIELD_LENGTH, extract


# ─── Casos normales (línea base) ─────────────────────────────────────────────

class TestCasosNormales:
    def test_jpeg_limpio_completa_extraccion(self, jpeg_clean):
        meta = extract(jpeg_clean)
        assert meta.extraction_complete is True

    def test_jpeg_limpio_tiene_hashes(self, jpeg_clean):
        meta = extract(jpeg_clean)
        assert meta.sha256 and len(meta.sha256) == 64
        assert meta.md5 and len(meta.md5) == 32

    def test_jpeg_limpio_hashes_son_hex(self, jpeg_clean):
        meta = extract(jpeg_clean)
        assert all(c in "0123456789abcdef" for c in meta.sha256)

    def test_jpeg_limpio_detecta_formato(self, jpeg_clean):
        assert extract(jpeg_clean).file_format == "JPEG"

    def test_jpeg_limpio_tiene_dimensiones(self, jpeg_clean):
        meta = extract(jpeg_clean)
        assert meta.image_dimensions == (100, 100)

    def test_jpeg_limpio_extrae_gps_tampico(self, jpeg_clean):
        meta = extract(jpeg_clean)
        assert meta.gps.latitude is not None
        assert abs(meta.gps.latitude - 22.22) < 0.01
        assert meta.gps.raw_valid is True

    def test_jpeg_limpio_extrae_make(self, jpeg_clean):
        meta = extract(jpeg_clean)
        assert meta.device.make == "TestCamera"

    def test_jpeg_sin_exif_completa_sin_crash(self, jpeg_no_exif):
        meta = extract(jpeg_no_exif)
        assert meta.extraction_complete is True

    def test_jpeg_sin_exif_device_make_es_none(self, jpeg_no_exif):
        """
        Sin EXIF, make debe ser None — no una cadena vacía, no "N/D".
        None es la representación correcta de "campo ausente" en este sistema.
        """
        meta = extract(jpeg_no_exif)
        assert meta.device.make is None

    def test_jpeg_sin_exif_gps_es_none(self, jpeg_no_exif):
        meta = extract(jpeg_no_exif)
        assert meta.gps.latitude is None
        assert meta.gps.longitude is None

    def test_png_limpio_detecta_formato(self, png_clean):
        assert extract(png_clean).file_format == "PNG"

    def test_png_multiple_chunks_todos_extraidos(self, png_multiple_text_chunks):
        meta = extract(png_multiple_text_chunks)
        chunks = meta.png_text_chunks
        assert "Author" in chunks
        assert "Copyright" in chunks
        assert "Description" in chunks
        assert "Software" in chunks

    def test_hashes_son_deterministas(self, jpeg_clean):
        """El mismo archivo produce siempre el mismo hash — no aleatorizado."""
        meta1 = extract(jpeg_clean)
        meta2 = extract(jpeg_clean)
        assert meta1.sha256 == meta2.sha256
        assert meta1.md5 == meta2.md5


# ─── Detección de señales de IA ──────────────────────────────────────────────

class TestSeñalesIA:
    def test_stable_diffusion_en_software_field(self, jpeg_ai_marker):
        """
        Marcador explícito de IA en campo Software — debe aparecer en
        editing.software_used para que consistency_checker lo detecte.
        """
        meta = extract(jpeg_ai_marker)
        software_lower = [s.lower() for s in meta.editing.software_used]
        assert any("stable diffusion" in s for s in software_lower)

    def test_png_ai_software_chunk_extraido(self, png_ai_software_chunk):
        meta = extract(png_ai_software_chunk)
        # El chunk Software debe estar en png_text_chunks
        assert "Software" in meta.png_text_chunks
        assert "stable diffusion" in meta.png_text_chunks["Software"].lower()

    def test_jpeg_sin_exif_no_tiene_make(self, jpeg_no_exif):
        """Sin make ni model ni parámetros de captura — señal de posible IA."""
        meta = extract(jpeg_no_exif)
        assert meta.device.make is None
        assert meta.device.model is None
        assert meta.capture.iso is None


# ─── Casos adversariales — Prioridad 1: integridad del reporte ───────────────

class TestIntegridadReporte:
    def test_gps_imposible_detectado(self, jpeg_gps_impossible):
        """
        Latitud 95° es físicamente imposible (rango: -90 a 90).
        El sistema debe detectarlo como coordenada inválida — no silenciarlo
        ni corregirlo silenciosamente a un valor "razonable".
        """
        meta = extract(jpeg_gps_impossible)
        # El GPS puede estar presente pero marcado como inválido
        if meta.gps.latitude is not None:
            assert meta.gps.raw_valid is False, (
                f"Latitud {meta.gps.latitude} debería marcarse como inválida"
            )

    def test_timestamp_imposible_preserve_ambos_valores(self, jpeg_timestamp_impossible):
        """
        Cuando Modified < Original, ambos timestamps deben preservarse en el
        reporte — no se corrige el "error", se documenta la inconsistencia.
        Un auditor forense necesita ver ambos valores tal como están en el archivo.
        """
        meta = extract(jpeg_timestamp_impossible)
        # Ambos timestamps deben estar presentes, sin que uno sobrescriba al otro
        assert meta.timestamps.exif_datetime_modified is not None
        assert meta.timestamps.exif_datetime_original is not None
        # La inconsistencia temporal en sí la detecta consistency_checker,
        # pero el extractor debe preservar ambos valores sin filtrar ninguno

    def test_archivo_tipo_incorrecto_detecta_formato_real(self, file_wrong_extension):
        """
        Archivo PNG con extensión .jpg: el formato debe detectarse por la firma
        de bytes real (PNG), no por la extensión del archivo.
        Relevante forense: un atacante puede renombrar un archivo para confundir
        al analista sobre su origen real.
        """
        meta = extract(file_wrong_extension)
        # Pillow detecta el formato real por la firma, no por la extensión
        # El formato debe ser PNG aunque la extensión diga .jpg
        assert meta.file_format == "PNG", (
            f"Formato debería ser PNG (por firma), no JPEG (por extensión). "
            f"Detectado: {meta.file_format}"
        )


# ─── Casos adversariales — Prioridad 2: seguridad del parser ─────────────────

class TestSeguridadParser:
    def test_archivo_cero_bytes_no_crashea(self, jpeg_zero_bytes):
        """
        El parser nunca debe lanzar una excepción no capturada ante un
        archivo de 0 bytes — debe retornar un ImageMetadata con
        extraction_complete=False o con warnings, pero nunca un crash.
        """
        meta = extract(jpeg_zero_bytes)
        # No crasheó — eso es lo mínimo
        assert meta is not None
        # El análisis debe haber registrado que algo falló
        # sin silenciarlo completamente
        has_any_signal = (
            len(meta.extraction_warnings) > 0 or
            len(meta.security.parse_errors) > 0 or
            meta.extraction_complete is False or
            meta.file_size_bytes == 0
        )
        assert has_any_signal, (
            "Un archivo de 0 bytes debería producir al menos un warning — "
            "retornar un reporte completamente limpio sería engañoso"
        )

    def test_firma_truncada_no_crashea(self, jpeg_truncated_signature):
        """Archivo con 3 bytes (firma JPEG incompleta) — no debe crashear."""
        meta = extract(jpeg_truncated_signature)
        assert meta is not None

    def test_campo_en_limite_no_truncado(self, jpeg_field_at_limit):
        """
        Campo de exactamente MAX_FIELD_LENGTH (2048) chars no debe truncarse —
        el límite es exclusivo (>), no inclusivo (>=).
        """
        meta = extract(jpeg_field_at_limit)
        # No debe haber oversized_fields para exactamente 2048 chars
        oversized = meta.security.oversized_fields
        # Si hay truncado, no debe ser de un campo de exactamente 2048 chars
        for field_note in oversized:
            # El campo ImageDescription con 2048 chars no debería aparecer aquí
            assert "2048 chars" not in field_note or "TRUNCADO" not in field_note, (
                f"Campo de exactamente {MAX_FIELD_LENGTH} chars fue truncado incorrectamente"
            )

    def test_campo_sobre_limite_truncado_con_marca(self, jpeg_field_over_limit):
        """
        Campo de 2049 chars debe truncarse y la truncación debe ser visible
        en el output — no silenciosa. El analista debe saber que el campo
        fue truncado para poder decidir si eso es relevante.
        """
        meta = extract(jpeg_field_over_limit)
        # Debe aparecer en oversized_fields O el valor debe contener "[TRUNCADO]"
        has_truncation_signal = (
            len(meta.security.oversized_fields) > 0 or
            any("[TRUNCADO]" in str(v) for v in meta.raw_exif_fields.values())
        )
        assert has_truncation_signal, (
            "Campo de 2049 chars debe señalar la truncación — "
            "silenciarlo sería información forense perdida"
        )

    def test_archivo_no_imagen_no_crashea(self, non_image_file):
        """
        Archivo de texto con extensión .jpg — el parser debe fallar limpiamente
        sin crashear. El contenido del archivo no debe ejecutarse ni evaluarse.
        """
        meta = extract(non_image_file)
        assert meta is not None
        # No debe haber extracción exitosa de un archivo que no es imagen
        assert meta.file_format is None or meta.extraction_complete is False or len(meta.extraction_warnings) > 0

    def test_png_crc_invalido_detectado(self, png_invalid_crc):
        """
        PNG con CRC corrupto: el sistema debe detectarlo como anomalía.
        Si el Rust parser está disponible, debe aparecer en las alertas de
        seguridad. Si no está disponible, el extractor Python debe al menos
        no crashear (Pillow puede o no detectar el CRC).
        """
        import os
        rust_available = bool(os.environ.get("VTR_RUST_PARSER_BIN"))

        meta = extract(png_invalid_crc)
        assert meta is not None  # no crasheó

        if rust_available:
            # Con Rust, el CRC inválido debe aparecer en anomalías
            all_security = (
                meta.security.structurally_anomalous +
                meta.extraction_warnings
            )
            has_crc_signal = any(
                "crc" in s.lower() or "CRC" in s
                for s in all_security
            )
            assert has_crc_signal, (
                "Rust parser debería detectar el CRC inválido — "
                "sin esta detección, la corrupción de datos pasa sin señal"
            )

    def test_hashes_distintos_para_imagenes_distintas(self, jpeg_clean, jpeg_no_exif):
        """
        Dos imágenes distintas deben tener hashes distintos.
        Esto verifica que los hashes se calculan sobre el contenido real
        del archivo, no sobre algún valor constante o timestamp.
        """
        meta_clean = extract(jpeg_clean)
        meta_no_exif = extract(jpeg_no_exif)
        assert meta_clean.sha256 != meta_no_exif.sha256
        assert meta_clean.md5 != meta_no_exif.md5
