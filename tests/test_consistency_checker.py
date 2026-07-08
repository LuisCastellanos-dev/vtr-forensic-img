"""
vtr-forensic-img — Tests adversariales
tests/test_consistency_checker.py

Cobertura de core/consistency_checker.py — el módulo que conecta
los hallazgos técnicos con el lenguaje forense que un auditor usa.

CRITERIO ESPECÍFICO DE ESTE MÓDULO:
  Un hallazgo que el checker no detecta es información forense perdida.
  Un hallazgo que el checker detecta incorrectamente es información
  forense falsa — igual de dañino en un contexto de auditoría real.
  Los tests verifican ambos casos con igual rigor.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.consistency_checker import check
from core.metadata_extractor import extract


class TestDeteccionAI:
    def test_marcador_explicito_ai_detectado(self, jpeg_ai_marker):
        meta = extract(jpeg_ai_marker)
        report = check(meta)
        assert report.ai_signals.explicit_ai_software_marker is True

    def test_marcador_ai_produce_hallazgo_alta_relevancia(self, jpeg_ai_marker):
        meta = extract(jpeg_ai_marker)
        report = check(meta)
        high_findings = [f for f in report.findings if f.relevance == "ALTA"]
        assert len(high_findings) >= 1, (
            "Marcador explícito de IA debe producir al menos un hallazgo ALTA"
        )

    def test_sin_metadata_camara_detectado(self, jpeg_no_exif):
        meta = extract(jpeg_no_exif)
        report = check(meta)
        assert report.ai_signals.no_camera_metadata is True

    def test_jpeg_limpio_no_tiene_marcador_ai(self, jpeg_clean):
        """
        Imagen con metadata de cámara real no debe ser marcada como IA.
        Falsos positivos en un sistema forense son tan dañinos como
        falsos negativos.
        """
        meta = extract(jpeg_clean)
        report = check(meta)
        assert report.ai_signals.explicit_ai_software_marker is False

    def test_png_ai_chunk_detectado(self, png_ai_software_chunk):
        meta = extract(png_ai_software_chunk)
        report = check(meta)
        assert report.ai_signals.explicit_ai_software_marker is True

    def test_nivel_riesgo_alto_con_marcador_ai(self, jpeg_ai_marker):
        meta = extract(jpeg_ai_marker)
        report = check(meta)
        assert report.risk_level == "ALTO"

    def test_nivel_riesgo_bajo_imagen_limpia(self, jpeg_clean):
        meta = extract(jpeg_clean)
        report = check(meta)
        assert report.risk_level in ("BAJO", "BAJO-MEDIO")


class TestDeteccionTimestamps:
    def test_timestamp_imposible_produce_hallazgo(self, jpeg_timestamp_impossible):
        """
        Modified < Original: debe producir un hallazgo ALTA.
        Esta inconsistencia es una señal forense directa — no tiene
        explicación técnica inocente en condiciones normales.
        """
        meta = extract(jpeg_timestamp_impossible)
        report = check(meta)
        timestamp_findings = [
            f for f in report.findings if f.category == "Timestamps"
        ]
        assert len(timestamp_findings) >= 1, (
            "DateTime Modified anterior a DateTimeOriginal debe producir hallazgo"
        )
        high = [f for f in timestamp_findings if f.relevance == "ALTA"]
        assert len(high) >= 1, "La inconsistencia temporal debe ser ALTA relevancia"

    def test_timestamp_imposible_nivel_riesgo_alto(self, jpeg_timestamp_impossible):
        meta = extract(jpeg_timestamp_impossible)
        report = check(meta)
        assert report.risk_level == "ALTO"


class TestDeteccionGPS:
    def test_gps_valido_no_produce_hallazgo_gps(self, jpeg_clean):
        """GPS de Tampico (22.22°N, 97.86°W) debe pasar sin hallazgos GPS."""
        meta = extract(jpeg_clean)
        report = check(meta)
        gps_findings = [f for f in report.findings if f.category == "GPS"]
        assert len(gps_findings) == 0, (
            f"GPS válido no debe producir hallazgos. "
            f"Hallazgos encontrados: {[f.description for f in gps_findings]}"
        )

    def test_gps_imposible_produce_hallazgo(self, jpeg_gps_impossible):
        meta = extract(jpeg_gps_impossible)
        report = check(meta)
        # Si el GPS fue parseado como imposible, debe aparecer en hallazgos
        if meta.gps.latitude is not None and not meta.gps.raw_valid:
            gps_findings = [f for f in report.findings if f.category == "GPS"]
            assert len(gps_findings) >= 1


class TestProveniencia:
    def test_resumen_incluye_dispositivo_si_existe(self, jpeg_clean):
        meta = extract(jpeg_clean)
        report = check(meta)
        assert "TestCamera" in report.provenance_summary

    def test_resumen_incluye_fecha_captura_si_existe(self, jpeg_clean):
        meta = extract(jpeg_clean)
        report = check(meta)
        assert "2026" in report.provenance_summary

    def test_resumen_incluye_nivel_riesgo(self, jpeg_clean):
        meta = extract(jpeg_clean)
        report = check(meta)
        assert "Nivel de riesgo" in report.provenance_summary

    def test_hallazgos_ordenados_por_relevancia(self, jpeg_ai_marker):
        """
        Los hallazgos deben ordenarse ALTA antes que MEDIA antes que BAJA —
        un auditor que lee solo el primer hallazgo debe ver el más importante.
        """
        meta = extract(jpeg_ai_marker)
        report = check(meta)
        if len(report.findings) > 1:
            order = {"ALTA": 0, "MEDIA": 1, "BAJA": 2}
            for i in range(len(report.findings) - 1):
                assert order[report.findings[i].relevance] <= order[report.findings[i+1].relevance], (
                    f"Hallazgos fuera de orden: "
                    f"{report.findings[i].relevance} antes de {report.findings[i+1].relevance}"
                )
