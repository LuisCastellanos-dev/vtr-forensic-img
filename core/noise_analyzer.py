"""
vtr-forensic-img v0.3.0
core/noise_analyzer.py

Análisis de consistencia de ruido de sensor (PRNU).

QUÉ DETECTA:
  Cada sensor fotográfico tiene un patrón de ruido único (Photo
  Response Non-Uniformity, PRNU) causado por imperfecciones en la
  fabricación del silicio. Este ruido es:

  - Consistente en toda la imagen — el mismo sensor produce el
    mismo patrón de ruido en cada foto que toma.
  - Característico del sensor — funciona como una "huella digital"
    del dispositivo físico.
  - Ausente en imágenes de IA — los generadores no tienen sensor
    físico, así que producen "ruido" sintético que es estadística-
    mente distinto del ruido de un sensor real.

CÓMO FUNCIONA:
  1. Extrae el ruido de la imagen separándolo del contenido visual
     (filtro de Wiener simplificado: imagen - suavizado = ruido)
  2. Analiza la distribución estadística del ruido:
     - Varianza del ruido por regiones
     - Uniformidad de la varianza entre regiones (un sensor real
       tiene varianza de ruido uniforme; IA no)
     - Distribución del ruido (sensor real → Gaussiana; IA → otra)
  3. Compara la correlación de ruido entre regiones no adyacentes
     (sensor real → correlacionadas; IA → independientes)

LIMITACIONES HONESTAS:
  1. La recompresión JPEG destruye el ruido fino del sensor —
     imágenes muy comprimidas (calidad < 70) no son analizables
     por este método.
  2. El suavizado agresivo (denoise) en la cámara o en post-proceso
     también elimina el PRNU.
  3. Imágenes pequeñas (<200px) no tienen suficiente área para
     comparar regiones de forma significativa.
"""

from __future__ import annotations

import io
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from PIL import Image, ImageFilter

logger = logging.getLogger(__name__)

MIN_DIMENSION = 200
MAX_IMAGE_PIXELS = 50 * 1024 * 1024
REGION_SIZE = 64  # tamaño de las regiones para análisis de uniformidad


@dataclass
class NoiseResult:
    applicable: bool = True
    skip_reason: str = ""

    # Estadísticas globales del ruido
    noise_mean: float | None = None
    noise_std: float | None = None

    # Uniformidad de varianza entre regiones
    region_variance_mean: float | None = None
    region_variance_std: float | None = None
    variance_uniformity: float | None = None  # std/mean — más bajo = más uniforme

    # Distribución
    noise_skewness: float | None = None
    noise_kurtosis: float | None = None
    is_gaussian_like: bool | None = None

    # Correlación inter-regional
    cross_region_correlation: float | None = None
    regions_analyzed: int = 0

    # Ruido por canal
    noise_std_r: float | None = None
    noise_std_g: float | None = None
    noise_std_b: float | None = None
    channel_noise_ratio_bg: float | None = None  # B/G — sensor real: >1.1

    # Hallazgos
    findings: list[str] = field(default_factory=list)
    ai_relevant: str = ""
    confidence: str = ""
    caveats: list[str] = field(default_factory=list)


def _extract_noise(gray: np.ndarray) -> np.ndarray:
    """
    Extrae el ruido residual de una imagen en escala de grises.

    Método: imagen original - imagen suavizada = ruido residual.
    El suavizado se hace con filtro Gaussiano (sigma=2) que preserva
    las estructuras grandes y elimina las variaciones finas (ruido).
    """
    img_pil = Image.fromarray(gray.astype(np.uint8))
    smoothed = img_pil.filter(ImageFilter.GaussianBlur(radius=2))
    smoothed_arr = np.array(smoothed, dtype=np.float64)
    noise = gray.astype(np.float64) - smoothed_arr
    return noise


def _extract_noise_rgb(arr: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Extrae ruido residual por canal R, G, B."""
    noise_r = _extract_noise(arr[:, :, 0])
    noise_g = _extract_noise(arr[:, :, 1])
    noise_b = _extract_noise(arr[:, :, 2])
    return noise_r, noise_g, noise_b


def _region_variances(noise: np.ndarray, region_size: int = REGION_SIZE) -> list[float]:
    """Calcula la varianza del ruido en regiones no superpuestas."""
    h, w = noise.shape
    variances = []

    for y in range(0, h - region_size + 1, region_size):
        for x in range(0, w - region_size + 1, region_size):
            region = noise[y:y + region_size, x:x + region_size]
            variances.append(float(np.var(region)))

    return variances


def _cross_region_correlation(noise: np.ndarray, region_size: int = REGION_SIZE) -> float:
    """
    Correlación de ruido entre regiones no adyacentes.

    Sensor real: regiones distantes tienen ruido correlacionado
    (mismo PRNU en todo el sensor).
    IA: regiones distantes tienen ruido independiente (no hay sensor).
    """
    h, w = noise.shape
    regions = []

    for y in range(0, h - region_size + 1, region_size):
        for x in range(0, w - region_size + 1, region_size):
            region = noise[y:y + region_size, x:x + region_size].flatten()
            regions.append(region)

    if len(regions) < 4:
        return 0.0

    # Comparar regiones no adyacentes (esquinas opuestas)
    correlations = []
    # Primera vs última
    r0 = regions[0]
    r_last = regions[-1]
    if len(r0) == len(r_last) and np.std(r0) > 1e-10 and np.std(r_last) > 1e-10:
        corr = float(np.corrcoef(r0, r_last)[0, 1])
        if not math.isnan(corr):
            correlations.append(abs(corr))

    # Segunda vs penúltima
    if len(regions) >= 4:
        r1 = regions[1]
        r_pen = regions[-2]
        if len(r1) == len(r_pen) and np.std(r1) > 1e-10 and np.std(r_pen) > 1e-10:
            corr = float(np.corrcoef(r1, r_pen)[0, 1])
            if not math.isnan(corr):
                correlations.append(abs(corr))

    # Cuartos
    quarter = len(regions) // 4
    if quarter > 0 and 3 * quarter < len(regions):
        rq1 = regions[quarter]
        rq3 = regions[3 * quarter]
        if len(rq1) == len(rq3) and np.std(rq1) > 1e-10 and np.std(rq3) > 1e-10:
            corr = float(np.corrcoef(rq1, rq3)[0, 1])
            if not math.isnan(corr):
                correlations.append(abs(corr))

    return round(float(np.mean(correlations)), 4) if correlations else 0.0


def _interpret(result: NoiseResult) -> None:
    """Interpreta los hallazgos de ruido en lenguaje forense."""
    indicators = []

    # Uniformidad de varianza
    if result.variance_uniformity is not None:
        if result.variance_uniformity < 0.1:
            indicators.append(
                f"Varianza de ruido excesivamente uniforme "
                f"(coef. variación={result.variance_uniformity:.3f}) — "
                f"sensor real produce varianza menos uniforme por diferencias "
                f"en la respuesta del silicio entre regiones"
            )
        elif result.variance_uniformity > 1.0:
            indicators.append(
                f"Varianza de ruido muy irregular "
                f"(coef. variación={result.variance_uniformity:.3f}) — "
                f"puede indicar composición o edición localizada"
            )

    # Gaussianidad del ruido
    if result.is_gaussian_like is False:
        indicators.append(
            f"Distribución de ruido no Gaussiana "
            f"(kurtosis={result.noise_kurtosis:.2f}, "
            f"skewness={result.noise_skewness:.2f}) — "
            f"ruido de sensor real es típicamente Gaussiano"
        )

    # Correlación inter-regional baja
    if result.cross_region_correlation is not None:
        if result.cross_region_correlation < 0.02:
            indicators.append(
                f"Correlación de ruido inter-regional muy baja "
                f"({result.cross_region_correlation:.4f}) — "
                f"sensor real tiene PRNU correlacionado en toda la imagen"
            )

    # Ratio de ruido entre canales
    if result.channel_noise_ratio_bg is not None:
        if 0.95 < result.channel_noise_ratio_bg < 1.05:
            indicators.append(
                f"Ruido B/G casi idéntico ({result.channel_noise_ratio_bg:.3f}) — "
                f"sensor CMOS real tiene más ruido en canal azul (ratio >1.1)"
            )

    result.findings.extend(indicators)

    if len(indicators) >= 3:
        result.ai_relevant = "ALTA sospecha de ruido sintético (no-sensor)"
        result.confidence = "MODERADA-ALTA — múltiples indicadores de ruido coinciden"
    elif len(indicators) >= 2:
        result.ai_relevant = "MODERADA sospecha de ruido sintético"
        result.confidence = "MODERADA — requiere cruce con otros análisis"
    elif len(indicators) >= 1:
        result.ai_relevant = "BAJA sospecha — un indicador no es concluyente"
        result.confidence = "BAJA — puede tener causas no-IA"
    else:
        result.ai_relevant = "Sin indicadores de ruido sintético"
        result.confidence = "Patrón de ruido consistente con sensor real"

    result.caveats.append(
        "La recompresión JPEG destruye ruido fino del sensor — "
        "imágenes muy comprimidas (calidad <70) no son analizables."
    )
    result.caveats.append(
        "El suavizado (denoise) en cámara o post-proceso "
        "también elimina el PRNU."
    )


def analyze(image_source: str | Path | bytes) -> NoiseResult:
    """
    Analiza la consistencia de ruido de una imagen.

    Args:
        image_source: ruta de archivo, Path, o bytes crudos.

    Returns:
        NoiseResult con estadísticas de ruido, uniformidad,
        correlación inter-regional, y hallazgos forenses.
    """
    result = NoiseResult()

    try:
        if isinstance(image_source, (str, Path)):
            path = Path(image_source)
            if not path.exists():
                result.applicable = False
                result.skip_reason = f"archivo no encontrado: {image_source}"
                return result
            img = Image.open(path)
        elif isinstance(image_source, bytes):
            if not image_source:
                result.applicable = False
                result.skip_reason = "bytes vacíos"
                return result
            img = Image.open(io.BytesIO(image_source))
        else:
            result.applicable = False
            result.skip_reason = f"Tipo no soportado: {type(image_source)}"
            return result

        w, h = img.size
        if w * h > MAX_IMAGE_PIXELS:
            result.applicable = False
            result.skip_reason = f"Imagen demasiado grande ({w}x{h})"
            img.close()
            return result

        if w < MIN_DIMENSION or h < MIN_DIMENSION:
            result.applicable = False
            result.skip_reason = (
                f"Imagen demasiado pequeña ({w}x{h}) para análisis "
                f"de ruido — mínimo {MIN_DIMENSION}x{MIN_DIMENSION}"
            )
            img.close()
            return result

        arr = np.array(img.convert("RGB"), dtype=np.uint8)
        gray = np.array(img.convert("L"), dtype=np.uint8)
        img.close()

        # Extraer ruido residual (escala de grises)
        noise = _extract_noise(gray)

        # Estadísticas globales
        result.noise_mean = round(float(np.mean(noise)), 4)
        result.noise_std = round(float(np.std(noise)), 4)

        # Uniformidad de varianza por regiones
        variances = _region_variances(noise)
        result.regions_analyzed = len(variances)

        if variances:
            var_mean = float(np.mean(variances))
            var_std = float(np.std(variances))
            result.region_variance_mean = round(var_mean, 6)
            result.region_variance_std = round(var_std, 6)
            result.variance_uniformity = round(
                var_std / var_mean if var_mean > 1e-10 else 0.0, 4
            )

        # Distribución del ruido
        from scipy import stats as sp_stats
        noise_flat = noise.flatten()

        if len(noise_flat) > 100 and np.std(noise_flat) > 1e-8:
            sk = float(sp_stats.skew(noise_flat))
            ku = float(sp_stats.kurtosis(noise_flat, fisher=False))
            result.noise_skewness = round(sk, 4) if not math.isnan(sk) else 0.0
            result.noise_kurtosis = round(ku, 4) if not math.isnan(ku) else 0.0
            # Gaussiana: skewness ~0, kurtosis ~3
            result.is_gaussian_like = (
                abs(result.noise_skewness) < 0.5 and
                abs(result.noise_kurtosis - 3.0) < 1.5
            )
        else:
            result.noise_skewness = 0.0
            result.noise_kurtosis = 0.0
            result.is_gaussian_like = None

        # Correlación inter-regional
        result.cross_region_correlation = _cross_region_correlation(noise)

        # Ruido por canal
        noise_r, noise_g, noise_b = _extract_noise_rgb(arr)
        result.noise_std_r = round(float(np.std(noise_r)), 4)
        result.noise_std_g = round(float(np.std(noise_g)), 4)
        result.noise_std_b = round(float(np.std(noise_b)), 4)

        if result.noise_std_g > 1e-10:
            result.channel_noise_ratio_bg = round(
                result.noise_std_b / result.noise_std_g, 4
            )

        _interpret(result)

    except Exception as e:
        result.applicable = False
        result.skip_reason = f"Error durante análisis de ruido: {str(e)[:200]}"
        logger.error("Noise analysis error: %s", str(e))

    return result
