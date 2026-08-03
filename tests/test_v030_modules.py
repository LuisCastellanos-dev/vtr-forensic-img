"""
vtr-forensic-img — Tests v0.3.0
tests/test_v030_modules.py

Cobertura de los cuatro módulos del roadmap v0.3.0:
  1. quantization_analyzer.py — tablas DQT JPEG y fingerprinting
  2. frequency_analyzer.py   — espectro FFT y pendiente espectral
  3. noise_analyzer.py       — consistencia de ruido PRNU
  4. entropy_analyzer.py     — EntropyProfile (extensión v0.3.0)

PRINCIPIO: ningún test depende de archivos externos. Todas las imágenes
se construyen programáticamente con propiedades específicas y controladas.
Las imágenes para frequency_analyzer y noise_analyzer deben tener al
menos 128px y 200px respectivamente — las fixtures de conftest.py (100px)
no son suficientes para estos módulos.
"""

from __future__ import annotations

import io
import struct
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from core.quantization_analyzer import analyze as quant_analyze
from core.frequency_analyzer import analyze as freq_analyze
from core.noise_analyzer import analyze as noise_analyze
from core.entropy_analyzer import analyze as entropy_analyze


# ─── Fixtures específicas v0.3.0 ─────────────────────────────────────────────

def _make_jpeg_bytes(width: int, height: int, quality: int = 85) -> bytes:
    """JPEG mínimo válido de tamaño y calidad controlados."""
    img = Image.new("RGB", (width, height), color=(128, 64, 32))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=quality)
    return buf.getvalue()


def _make_jpeg_noise(width: int, height: int, quality: int = 85) -> bytes:
    """JPEG con ruido aleatorio — mayor varianza espectral."""
    rng = np.random.default_rng(seed=42)
    arr = rng.integers(0, 256, (height, width, 3), dtype=np.uint8)
    img = Image.fromarray(arr, mode="RGB")
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=quality)
    return buf.getvalue()


def _make_png_bytes(width: int, height: int) -> bytes:
    """PNG limpio — no tiene tablas DQT."""
    img = Image.new("RGB", (width, height), color=(64, 128, 32))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def jpeg_128(tmp_path) -> Path:
    """JPEG 128×128 — mínimo para frequency_analyzer."""
    p = tmp_path / "jpeg_128.jpg"
    p.write_bytes(_make_jpeg_bytes(128, 128))
    return p


@pytest.fixture
def jpeg_200(tmp_path) -> Path:
    """JPEG 200×200 — mínimo para noise_analyzer."""
    p = tmp_path / "jpeg_200.jpg"
    p.write_bytes(_make_jpeg_bytes(200, 200))
    return p


@pytest.fixture
def jpeg_256(tmp_path) -> Path:
    """JPEG 256×256 — suficiente para todos los módulos."""
    p = tmp_path / "jpeg_256.jpg"
    p.write_bytes(_make_jpeg_bytes(256, 256))
    return p


@pytest.fixture
def jpeg_256_noise(tmp_path) -> Path:
    """JPEG 256×256 con ruido aleatorio — mayor varianza espectral."""
    p = tmp_path / "jpeg_256_noise.jpg"
    p.write_bytes(_make_jpeg_noise(256, 256))
    return p


@pytest.fixture
def jpeg_bytes_raw() -> bytes:
    """JPEG como bytes crudos — cubre la rama bytes en analyze()."""
    return _make_jpeg_bytes(128, 128)


@pytest.fixture
def png_128(tmp_path) -> Path:
    """PNG 128×128 — no tiene tablas DQT."""
    p = tmp_path / "png_128.png"
    p.write_bytes(_make_png_bytes(128, 128))
    return p


@pytest.fixture
def jpeg_small(tmp_path) -> Path:
    """JPEG 64×64 — por debajo del mínimo de frequency y noise analyzer."""
    p = tmp_path / "jpeg_small.jpg"
    p.write_bytes(_make_jpeg_bytes(64, 64))
    return p


@pytest.fixture
def empty_file(tmp_path) -> Path:
    """Archivo vacío — todos los módulos deben manejar esto sin crash."""
    p = tmp_path / "empty.jpg"
    p.write_bytes(b"")
    return p


@pytest.fixture
def not_jpeg(tmp_path) -> Path:
    """Bytes aleatorios con extensión .jpg — no es un JPEG válido."""
    p = tmp_path / "not_jpeg.jpg"
    p.write_bytes(b"\x00\x01\x02\x03\x04\x05")
    return p


# ─── 1. QUANTIZATION ANALYZER ────────────────────────────────────────────────

class TestQuantizationAnalyzer:

    def test_jpeg_valido_retorna_applicable(self, jpeg_256):
        r = quant_analyze(jpeg_256)
        assert r.applicable is True

    def test_tablas_extraidas(self, jpeg_256):
        """JPEG con color debe tener al menos una tabla DQT."""
        r = quant_analyze(jpeg_256)
        assert r.num_tables >= 1
        assert len(r.tables) == r.num_tables

    def test_calidad_estimada_en_rango(self, jpeg_256):
        """La calidad estimada debe estar entre 1 y 100."""
        r = quant_analyze(jpeg_256)
        if r.estimated_quality is not None:
            assert 1 <= r.estimated_quality <= 100

    def test_calidad_estimada_coherente_con_parametro(self, tmp_path):
        """JPEG guardado a calidad 95 debe estimar calidad cercana a 95."""
        p = tmp_path / "q95.jpg"
        p.write_bytes(_make_jpeg_bytes(128, 128, quality=95))
        r = quant_analyze(p)
        if r.estimated_quality is not None:
            assert abs(r.estimated_quality - 95) <= 10

    def test_tabla_luminancia_presente(self, jpeg_256):
        """Debe haber al menos una tabla de luminancia (ID=0)."""
        r = quant_analyze(jpeg_256)
        lum = [t for t in r.tables if t.table_id == 0]
        assert len(lum) >= 1

    def test_tabla_valores_64_elementos(self, jpeg_256):
        """Cada tabla DQT debe tener exactamente 64 valores."""
        r = quant_analyze(jpeg_256)
        for table in r.tables:
            assert len(table.values) == 64

    def test_findings_no_vacio(self, jpeg_256):
        """El análisis siempre produce al menos un finding."""
        r = quant_analyze(jpeg_256)
        assert len(r.findings) > 0

    def test_ai_relevant_presente(self, jpeg_256):
        """ai_relevant debe estar poblado con texto."""
        r = quant_analyze(jpeg_256)
        assert r.ai_relevant and len(r.ai_relevant) > 0

    def test_rama_bytes_raw(self, jpeg_bytes_raw):
        """analyze() acepta bytes crudos además de Path."""
        r = quant_analyze(jpeg_bytes_raw)
        assert r.applicable is True
        assert r.num_tables >= 1

    def test_png_no_aplicable(self, png_128):
        """PNG no tiene tablas DQT — debe retornar applicable=False."""
        r = quant_analyze(png_128)
        assert r.applicable is False
        assert r.skip_reason

    def test_archivo_vacio_no_aplicable(self, empty_file):
        r = quant_analyze(empty_file)
        assert r.applicable is False
        assert r.skip_reason

    def test_archivo_inexistente_no_aplicable(self, tmp_path):
        r = quant_analyze(tmp_path / "no_existe.jpg")
        assert r.applicable is False
        assert r.skip_reason

    def test_no_jpeg_no_aplicable(self, not_jpeg):
        r = quant_analyze(not_jpeg)
        assert r.applicable is False
        assert "SOI" in r.skip_reason or "JPEG" in r.skip_reason

    def test_reproducibilidad(self, jpeg_256):
        """Mismo archivo → mismo resultado."""
        r1 = quant_analyze(jpeg_256)
        r2 = quant_analyze(jpeg_256)
        assert r1.num_tables == r2.num_tables
        assert r1.estimated_quality == r2.estimated_quality
        assert r1.is_standard_table == r2.is_standard_table

    def test_is_standard_table_es_booleano(self, jpeg_256):
        r = quant_analyze(jpeg_256)
        assert isinstance(r.is_standard_table, bool)

    def test_tipo_no_soportado_no_aplicable(self):
        """Tipo de input no soportado → applicable=False, no excepción."""
        r = quant_analyze(12345)
        assert r.applicable is False


# ─── 2. FREQUENCY ANALYZER ───────────────────────────────────────────────────

class TestFrequencyAnalyzer:

    def test_jpeg_valido_retorna_applicable(self, jpeg_128):
        r = freq_analyze(jpeg_128)
        assert r.applicable is True

    def test_pendiente_espectral_calculada(self, jpeg_128):
        """spectral_slope debe estar presente y ser un número finito."""
        r = freq_analyze(jpeg_128)
        assert r.spectral_slope is not None
        assert isinstance(r.spectral_slope, float)
        assert r.spectral_slope != float('inf')
        assert r.spectral_slope != float('-inf')

    def test_r_squared_en_rango(self, jpeg_128):
        """R² del ajuste log-log debe estar entre 0 y 1."""
        r = freq_analyze(jpeg_128)
        if r.slope_r_squared is not None:
            assert 0.0 <= r.slope_r_squared <= 1.0

    def test_ratios_energia_suman_uno(self, jpeg_128):
        """Los ratios de energía alta y baja deben sumar ~1.0."""
        r = freq_analyze(jpeg_128)
        if r.high_freq_energy_ratio is not None and r.low_freq_energy_ratio is not None:
            total = r.high_freq_energy_ratio + r.low_freq_energy_ratio
            assert abs(total - 1.0) < 0.01

    def test_simetria_espectral_en_rango(self, jpeg_128):
        """La simetría espectral debe estar entre 0 y 1."""
        r = freq_analyze(jpeg_128)
        if r.spectral_symmetry is not None:
            assert 0.0 <= r.spectral_symmetry <= 1.0

    def test_picos_periodicos_no_negativo(self, jpeg_128):
        r = freq_analyze(jpeg_128)
        assert r.periodic_peaks_detected >= 0

    def test_findings_presentes(self, jpeg_128):
        """El análisis produce interpretación — findings y ai_relevant."""
        r = freq_analyze(jpeg_128)
        assert r.ai_relevant and len(r.ai_relevant) > 0
        assert r.confidence and len(r.confidence) > 0

    def test_caveats_presentes(self, jpeg_128):
        r = freq_analyze(jpeg_128)
        assert len(r.caveats) >= 2

    def test_imagen_pequena_no_aplicable(self, jpeg_small):
        """Imagen menor que MIN_DIMENSION → applicable=False."""
        r = freq_analyze(jpeg_small)
        assert r.applicable is False
        assert r.skip_reason

    def test_archivo_vacio_no_aplicable(self, empty_file):
        r = freq_analyze(empty_file)
        assert r.applicable is False

    def test_archivo_inexistente_no_aplicable(self, tmp_path):
        r = freq_analyze(tmp_path / "no_existe.jpg")
        assert r.applicable is False

    def test_rama_bytes_raw(self, jpeg_bytes_raw):
        """analyze() acepta bytes crudos."""
        r = freq_analyze(jpeg_bytes_raw)
        assert r.applicable is True
        assert r.spectral_slope is not None

    def test_bytes_vacios_no_aplicable(self):
        r = freq_analyze(b"")
        assert r.applicable is False

    def test_reproducibilidad(self, jpeg_256):
        """Mismo archivo → mismo resultado."""
        r1 = freq_analyze(jpeg_256)
        r2 = freq_analyze(jpeg_256)
        assert r1.spectral_slope == r2.spectral_slope
        assert r1.spectral_symmetry == r2.spectral_symmetry

    def test_imagen_ruido_vs_uniforme(self, jpeg_256, jpeg_256_noise):
        """
        Imagen con ruido tiene más energía en altas frecuencias
        que imagen de color uniforme.
        """
        r_uniform = freq_analyze(jpeg_256)
        r_noise = freq_analyze(jpeg_256_noise)
        if (r_uniform.high_freq_energy_ratio is not None and
                r_noise.high_freq_energy_ratio is not None):
            assert r_noise.high_freq_energy_ratio >= r_uniform.high_freq_energy_ratio

    def test_tipo_no_soportado_no_aplicable(self):
        r = freq_analyze(12345)
        assert r.applicable is False


# ─── 3. NOISE ANALYZER ───────────────────────────────────────────────────────

class TestNoiseAnalyzer:

    def test_jpeg_valido_retorna_applicable(self, jpeg_200):
        r = noise_analyze(jpeg_200)
        assert r.applicable is True

    def test_estadisticas_globales_calculadas(self, jpeg_200):
        """noise_mean y noise_std deben estar presentes."""
        r = noise_analyze(jpeg_200)
        assert r.noise_mean is not None
        assert r.noise_std is not None
        assert r.noise_std >= 0.0

    def test_varianza_uniformidad_calculada(self, jpeg_200):
        """variance_uniformity debe estar presente y ser >= 0."""
        r = noise_analyze(jpeg_200)
        if r.variance_uniformity is not None:
            assert r.variance_uniformity >= 0.0

    def test_regiones_analizadas_positivo(self, jpeg_200):
        """Al menos una región debe analizarse."""
        r = noise_analyze(jpeg_200)
        assert r.regions_analyzed > 0

    def test_ruido_por_canal_calculado(self, jpeg_200):
        """Los tres canales R, G, B deben tener noise_std calculado."""
        r = noise_analyze(jpeg_200)
        assert r.noise_std_r is not None
        assert r.noise_std_g is not None
        assert r.noise_std_b is not None
        assert r.noise_std_r >= 0.0
        assert r.noise_std_g >= 0.0
        assert r.noise_std_b >= 0.0

    def test_ratio_canal_bg_calculado(self, jpeg_200):
        """channel_noise_ratio_bg debe ser un número positivo."""
        r = noise_analyze(jpeg_200)
        if r.channel_noise_ratio_bg is not None:
            assert r.channel_noise_ratio_bg > 0.0

    def test_correlacion_inter_regional_en_rango(self, jpeg_200):
        """La correlación inter-regional debe estar entre 0 y 1."""
        r = noise_analyze(jpeg_200)
        if r.cross_region_correlation is not None:
            assert 0.0 <= r.cross_region_correlation <= 1.0

    def test_gaussianidad_calculada(self, jpeg_200):
        """is_gaussian_like debe ser bool o None — nunca otro tipo."""
        r = noise_analyze(jpeg_200)
        assert r.is_gaussian_like is None or isinstance(r.is_gaussian_like, bool)

    def test_ai_relevant_presente(self, jpeg_200):
        r = noise_analyze(jpeg_200)
        assert r.ai_relevant and len(r.ai_relevant) > 0

    def test_caveats_presentes(self, jpeg_200):
        r = noise_analyze(jpeg_200)
        assert len(r.caveats) >= 2

    def test_imagen_pequena_no_aplicable(self, jpeg_small):
        """Imagen menor que MIN_DIMENSION (200px) → applicable=False."""
        r = noise_analyze(jpeg_small)
        assert r.applicable is False
        assert r.skip_reason

    def test_archivo_vacio_no_aplicable(self, empty_file):
        r = noise_analyze(empty_file)
        assert r.applicable is False

    def test_archivo_inexistente_no_aplicable(self, tmp_path):
        r = noise_analyze(tmp_path / "no_existe.jpg")
        assert r.applicable is False

    def test_rama_bytes_raw(self):
        """analyze() acepta bytes crudos de imagen 200×200."""
        data = _make_jpeg_bytes(200, 200)
        r = noise_analyze(data)
        assert r.applicable is True
        assert r.noise_std is not None

    def test_bytes_vacios_no_aplicable(self):
        r = noise_analyze(b"")
        assert r.applicable is False

    def test_reproducibilidad(self, jpeg_256):
        """Mismo archivo → mismo resultado."""
        r1 = noise_analyze(jpeg_256)
        r2 = noise_analyze(jpeg_256)
        assert r1.noise_mean == r2.noise_mean
        assert r1.noise_std == r2.noise_std
        assert r1.variance_uniformity == r2.variance_uniformity

    def test_tipo_no_soportado_no_aplicable(self):
        r = noise_analyze(12345)
        assert r.applicable is False


# ─── 4. ENTROPY PROFILE (v0.3.0) ─────────────────────────────────────────────

class TestEntropyProfile:
    """
    Tests del EntropyProfile añadido en v0.3.0.
    El perfil es complementario — si falla, el resultado v0.2.0
    sigue siendo válido (profile puede ser None). Los tests verifican
    el camino normal: imagen suficientemente grande para que el perfil
    se calcule.
    """

    def test_profile_calculado_para_imagen_grande(self, jpeg_256):
        """Imagen 256×256 debe producir un EntropyProfile no-None."""
        r = entropy_analyze(jpeg_256)
        assert r.applicable is True
        assert r.profile is not None

    def test_skewness_y_kurtosis_presentes(self, jpeg_256):
        r = entropy_analyze(jpeg_256)
        assert r.profile is not None
        assert r.profile.skewness is not None
        assert r.profile.kurtosis is not None

    def test_kurtosis_positiva(self, jpeg_256):
        """Kurtosis de Fisher no-negativa para distribuciones reales."""
        r = entropy_analyze(jpeg_256)
        if r.profile and r.profile.kurtosis is not None:
            assert r.profile.kurtosis >= 0.0

    def test_gradientes_espaciales_calculados(self, jpeg_256):
        r = entropy_analyze(jpeg_256)
        assert r.profile is not None
        assert r.profile.spatial_gradient_mean is not None
        assert r.profile.spatial_gradient_std is not None
        assert r.profile.spatial_gradient_mean >= 0.0

    def test_entropia_por_canal_calculada(self, jpeg_256):
        r = entropy_analyze(jpeg_256)
        assert r.profile is not None
        assert r.profile.channel_entropy_r is not None
        assert r.profile.channel_entropy_g is not None
        assert r.profile.channel_entropy_b is not None
        # Entropía Shannon: 0.0 a 8.0
        for e in [r.profile.channel_entropy_r,
                  r.profile.channel_entropy_g,
                  r.profile.channel_entropy_b]:
            assert 0.0 <= e <= 8.0

    def test_correlaciones_inter_canal_en_rango(self, jpeg_256):
        r = entropy_analyze(jpeg_256)
        assert r.profile is not None
        for corr in [r.profile.channel_correlation_rg,
                     r.profile.channel_correlation_rb,
                     r.profile.channel_correlation_gb]:
            if corr is not None:
                assert -1.0 <= corr <= 1.0

    def test_multiscala_calculada(self, jpeg_256):
        """Las tres escalas (32, 64, 128) deben estar presentes."""
        r = entropy_analyze(jpeg_256)
        assert r.profile is not None
        assert r.profile.multiscale_32_mean is not None
        assert r.profile.multiscale_64_mean is not None
        assert r.profile.multiscale_128_mean is not None

    def test_multiscale_consistency_calculada(self, jpeg_256):
        r = entropy_analyze(jpeg_256)
        assert r.profile is not None
        assert r.profile.multiscale_consistency is not None
        assert r.profile.multiscale_consistency >= 0.0

    def test_ai_confidence_presente(self, jpeg_256):
        """ai_confidence debe tener texto."""
        r = entropy_analyze(jpeg_256)
        assert r.profile is not None
        assert r.profile.ai_confidence and len(r.profile.ai_confidence) > 0

    def test_ai_indicators_es_lista(self, jpeg_256):
        r = entropy_analyze(jpeg_256)
        assert r.profile is not None
        assert isinstance(r.profile.ai_indicators, list)

    def test_profile_none_para_imagen_pequena(self, tmp_path):
        """
        Imagen muy pequeña: el perfil puede ser None o el análisis
        no-aplicable — pero nunca debe lanzar una excepción.
        """
        p = tmp_path / "tiny.jpg"
        p.write_bytes(_make_jpeg_bytes(32, 32))
        r = entropy_analyze(p)
        # No debe lanzar — resultado puede ser applicable=False o profile=None
        assert r is not None

    def test_reproducibilidad_profile(self, jpeg_256):
        """Mismo archivo → mismo perfil."""
        r1 = entropy_analyze(jpeg_256)
        r2 = entropy_analyze(jpeg_256)
        assert r1.profile is not None
        assert r2.profile is not None
        assert r1.profile.skewness == r2.profile.skewness
        assert r1.profile.kurtosis == r2.profile.kurtosis
        assert r1.profile.multiscale_consistency == r2.profile.multiscale_consistency

    def test_profile_coherente_con_resultado_v020(self, jpeg_256):
        """
        El profile no debe contradecir el análisis v0.2.0:
        si global_entropy está en rango normal, el profile
        debe estar calculado (no None).
        """
        r = entropy_analyze(jpeg_256)
        if r.applicable and 0.0 < r.global_entropy < 7.8:
            assert r.profile is not None
