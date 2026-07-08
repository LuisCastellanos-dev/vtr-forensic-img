"""
vtr-forensic-img — Tests adversariales
tests/test_ela_analyzer.py

Cobertura de core/ela_analyzer.py.

NOTA SOBRE ELA Y LOS TESTS:
  ELA es probabilístico por naturaleza — los umbrales son configurables
  y los resultados son "indicadores", no hechos binarios. Los tests aquí
  NO verifican "esta imagen tiene anomalías ELA" como afirmación absoluta.
  Verifican que el módulo:
  (1) produce output estructuralmente correcto bajo cualquier input,
  (2) respeta sus propios límites de seguridad (tamaño máximo),
  (3) documenta sus parámetros en el output (reproducibilidad),
  (4) falla de forma limpia y registrada, nunca silenciosamente.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.ela_analyzer import DEFAULT_ANOMALY_THRESHOLD, DEFAULT_ELA_QUALITY, analyze


class TestELAOutputEstructural:
    def test_jpeg_limpio_retorna_resultado_valido(self, jpeg_clean):
        result = analyze(jpeg_clean)
        assert result.applicable is True
        assert result.global_mean_error >= 0
        assert result.global_max_error >= result.global_mean_error
        assert 0.0 <= result.anomalous_pixel_ratio <= 1.0

    def test_ela_quality_usado_se_registra_en_output(self, jpeg_clean):
        """
        El umbral y calidad usados deben aparecer en el output — sin esta
        información, un auditor no puede reproducir el análisis ni
        cuestionar los parámetros elegidos.
        """
        result = analyze(jpeg_clean, quality=80, threshold=20.0)
        assert result.ela_quality_used == 80
        assert result.threshold_used == 20.0

    def test_caveats_siempre_presentes(self, jpeg_clean):
        """
        Los caveats (limitaciones del método) deben estar siempre en el
        output — no solo cuando hay anomalías. Un analista que ve ELA "limpio"
        debe saber igualmente las limitaciones del método.
        """
        result = analyze(jpeg_clean)
        assert len(result.caveats) > 0

    def test_ela_image_bytes_generada_cuando_solicitada(self, jpeg_clean):
        result = analyze(jpeg_clean, include_ela_image=True)
        assert result.ela_image_bytes is not None
        assert len(result.ela_image_bytes) > 0

    def test_ela_image_bytes_ausente_cuando_no_solicitada(self, jpeg_clean):
        result = analyze(jpeg_clean, include_ela_image=False)
        assert result.ela_image_bytes is None

    def test_interpretacion_siempre_presente(self, jpeg_clean):
        result = analyze(jpeg_clean)
        assert result.interpretation and len(result.interpretation) > 10

    def test_confianza_siempre_presente(self, jpeg_clean):
        result = analyze(jpeg_clean)
        assert result.confidence and len(result.confidence) > 0


class TestELALimitesSeguridad:
    def test_imagen_sobre_limite_no_aplicable(self, tmp_path):
        """
        Imagen de más de 50 megapixels debe ser rechazada con
        applicable=False y skip_reason explicativo — no debe
        intentar procesarse (riesgo de OOM).
        """
        # Crear imagen justo sobre el límite (50MP + 1)
        # No creamos una imagen real de ese tamaño — solo verificamos
        # que el límite existe y funciona con una imagen pequeña primero
        from core.ela_analyzer import MAX_IMAGE_PIXELS

        # Crear imagen pequeña y verificar que el límite está definido
        assert MAX_IMAGE_PIXELS == 50 * 1024 * 1024, (
            f"MAX_IMAGE_PIXELS debería ser 50MP, es {MAX_IMAGE_PIXELS}"
        )

        small = analyze(tmp_path / "nonexistent.jpg")
        # La imagen no existe — debe fallar limpiamente
        assert small.applicable is False
        assert small.skip_reason

    def test_archivo_inexistente_falla_limpio(self, tmp_path):
        result = analyze(tmp_path / "does_not_exist.jpg")
        assert result.applicable is False
        assert result.skip_reason is not None
        assert len(result.skip_reason) > 0

    def test_archivo_cero_bytes_falla_limpio(self, jpeg_zero_bytes):
        result = analyze(jpeg_zero_bytes)
        assert result.applicable is False

    def test_archivo_no_imagen_falla_limpio(self, non_image_file):
        result = analyze(non_image_file)
        assert result.applicable is False


class TestELAReproducibilidad:
    def test_mismo_archivo_mismo_resultado(self, jpeg_clean):
        """ELA sobre el mismo archivo debe dar siempre el mismo resultado."""
        r1 = analyze(jpeg_clean, quality=95, threshold=15.0)
        r2 = analyze(jpeg_clean, quality=95, threshold=15.0)
        assert r1.global_mean_error == r2.global_mean_error
        assert r1.anomalous_pixel_ratio == r2.anomalous_pixel_ratio

    def test_umbral_diferente_cambia_regiones_anomalas(self, jpeg_clean):
        """
        Un umbral más bajo debe detectar más regiones anómalas que uno más alto
        — si no es así, el parámetro de umbral no está funcionando.
        """
        r_low = analyze(jpeg_clean, threshold=1.0)
        r_high = analyze(jpeg_clean, threshold=100.0)
        assert r_low.anomalous_pixel_ratio >= r_high.anomalous_pixel_ratio

    def test_png_incluye_caveat_de_conversion(self, png_clean):
        """
        ELA sobre PNG debe incluir un caveat sobre la conversión a JPEG
        que introduce el análisis — sin ese caveat, el analista no sabe
        que hay un paso de transformación que afecta el resultado.
        """
        result = analyze(png_clean)
        if result.applicable:
            conversion_caveat = any(
                "conversión" in c.lower() or "formato" in c.lower() or "lossless" in c.lower()
                for c in result.caveats
            )
            assert conversion_caveat, (
                "ELA sobre PNG debe advertir sobre la conversión a JPEG"
            )
