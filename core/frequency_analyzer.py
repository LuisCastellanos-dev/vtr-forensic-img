"""
vtr-forensic-img v0.3.0
core/frequency_analyzer.py

Análisis de frecuencia por FFT (Fast Fourier Transform).

QUÉ DETECTA:
  Las imágenes generadas por redes neuronales (GANs, diffusion models)
  dejan artefactos en el dominio de frecuencia que son invisibles a
  ojo pero detectables con FFT. Estos artefactos se manifiestan como:

  - Picos periódicos: repeticiones regulares en frecuencias específicas
    que no existen en fotos de sensores reales.
  - Caída de alta frecuencia: los generadores de IA tienen dificultad
    para producir ruido de alta frecuencia realista. Las fotos reales
    tienen más energía en altas frecuencias (ruido del sensor).
  - Simetría espectral anómala: algunos generadores producen espectros
    más simétricos de lo que una escena natural produciría.

CÓMO FUNCIONA:
  1. Convierte la imagen a escala de grises (luminancia)
  2. Aplica FFT 2D y calcula el espectro de potencia (magnitud²)
  3. Calcula el perfil radial de energía (energía por distancia al
     centro, que corresponde a frecuencia espacial)
  4. Mide la pendiente del espectro (slope) — las fotos naturales
     siguen una ley de potencia ~1/f², las imágenes de IA se desvían
  5. Detecta picos periódicos por encima del perfil esperado

REFERENCIA:
  Las imágenes naturales siguen una distribución espectral conocida
  como "1/f noise" o "pink noise" — la energía es inversamente
  proporcional al cuadrado de la frecuencia. Esta propiedad fue
  documentada por Field (1987) y es una constante estadística de
  escenas naturales capturadas por sensores reales.

LIMITACIONES HONESTAS:
  1. La pendiente espectral varía con el contenido de la imagen
     (una imagen de cielo tiene pendiente distinta a una de bosque).
  2. La recompresión JPEG atenúa las altas frecuencias — una foto
     real muy comprimida puede parecer "suave" como IA.
  3. Imágenes muy pequeñas (<128px) no tienen resolución espectral
     suficiente para un análisis significativo.
"""

from __future__ import annotations

import io
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from PIL import Image

logger = logging.getLogger(__name__)

MIN_DIMENSION = 128  # mínimo para análisis espectral significativo
MAX_IMAGE_PIXELS = 50 * 1024 * 1024


@dataclass
class FrequencyResult:
    applicable: bool = True
    skip_reason: str = ""

    # Espectro
    spectral_slope: float | None = None  # pendiente log-log del perfil radial
    slope_r_squared: float | None = None  # R² del ajuste lineal
    high_freq_energy_ratio: float | None = None  # energía en altas freq / total
    low_freq_energy_ratio: float | None = None  # energía en bajas freq / total

    # Detección de picos
    periodic_peaks_detected: int = 0
    peak_frequencies: list[float] = field(default_factory=list)

    # Simetría espectral
    spectral_symmetry: float | None = None  # 1.0 = perfectamente simétrico

    # Interpretación
    findings: list[str] = field(default_factory=list)
    ai_relevant: str = ""
    confidence: str = ""
    caveats: list[str] = field(default_factory=list)


def _compute_power_spectrum(gray: np.ndarray) -> np.ndarray:
    """
    Calcula el espectro de potencia 2D de una imagen en escala de grises.
    El espectro se centra (DC en el centro) y se normaliza.
    """
    f_transform = np.fft.fft2(gray.astype(np.float64))
    f_shifted = np.fft.fftshift(f_transform)
    power = np.abs(f_shifted) ** 2

    # Normalizar para que no dependa del tamaño de la imagen
    power = power / power.sum() if power.sum() > 0 else power
    return power


def _radial_profile(power: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """
    Calcula el perfil radial del espectro de potencia.
    Para cada distancia r desde el centro, promedia la energía en
    todos los píxeles a esa distancia — colapsa el espectro 2D a
    una curva 1D de energía vs frecuencia.

    Retorna (frequencies, energies) como arrays.
    """
    h, w = power.shape
    cy, cx = h // 2, w // 2
    max_r = min(cy, cx)

    # Crear mapa de distancias al centro
    y_grid, x_grid = np.ogrid[:h, :w]
    dist = np.sqrt((x_grid - cx) ** 2 + (y_grid - cy) ** 2).astype(int)

    # Promediar energía por radio
    energies = []
    frequencies = []
    for r in range(1, max_r):  # empezar en 1 para evitar DC component
        mask = dist == r
        if mask.any():
            energies.append(float(np.mean(power[mask])))
            frequencies.append(r)

    return np.array(frequencies, dtype=np.float64), np.array(energies, dtype=np.float64)


def _fit_spectral_slope(frequencies: np.ndarray, energies: np.ndarray) -> tuple[float, float]:
    """
    Ajusta una recta en el espacio log-log del perfil radial.
    La pendiente (slope) indica qué tan rápido cae la energía
    con la frecuencia:
    - Imágenes naturales: pendiente ~ -2.0 a -3.0 (ley 1/f²)
    - IA generativa: pendiente más suave (menos energía en altas freq)

    Retorna (slope, r_squared).
    """
    # Filtrar valores positivos para log
    valid = energies > 0
    if valid.sum() < 3:
        return 0.0, 0.0

    log_f = np.log10(frequencies[valid])
    log_e = np.log10(energies[valid])

    # Ajuste lineal por mínimos cuadrados
    coeffs = np.polyfit(log_f, log_e, 1)
    slope = coeffs[0]

    # R² del ajuste
    predicted = np.polyval(coeffs, log_f)
    ss_res = np.sum((log_e - predicted) ** 2)
    ss_tot = np.sum((log_e - np.mean(log_e)) ** 2)
    r_squared = 1.0 - (ss_res / ss_tot) if ss_tot > 0 else 0.0

    return round(float(slope), 4), round(float(r_squared), 4)


def _detect_peaks(frequencies: np.ndarray, energies: np.ndarray, threshold_std: float = 3.0) -> list[float]:
    """
    Detecta picos periódicos en el perfil radial.
    Un pico es una frecuencia donde la energía supera la tendencia
    esperada por más de threshold_std desviaciones estándar.
    """
    if len(energies) < 10:
        return []

    # Suavizar con media móvil para obtener la tendencia
    kernel_size = max(3, len(energies) // 20)
    if kernel_size % 2 == 0:
        kernel_size += 1
    kernel = np.ones(kernel_size) / kernel_size
    smoothed = np.convolve(energies, kernel, mode='same')

    # Residuos
    residuals = energies - smoothed
    std = np.std(residuals)

    if std < 1e-15:
        return []

    peaks = []
    for i, r in enumerate(residuals):
        if r > threshold_std * std:
            peaks.append(float(frequencies[i]))

    return peaks[:10]  # máximo 10 picos reportados


def _compute_symmetry(power: np.ndarray) -> float:
    """
    Mide la simetría del espectro de potencia.
    Un espectro perfectamente simétrico tiene score 1.0.
    Las imágenes naturales tienen simetría < 0.99 por las
    asimetrías del contenido de la escena.
    """
    h, w = power.shape
    # Comparar cuadrantes opuestos
    q1 = power[:h // 2, :w // 2]
    q3 = power[h // 2:h // 2 + q1.shape[0], w // 2:w // 2 + q1.shape[1]]

    if q1.shape != q3.shape or q1.size == 0:
        return 0.0

    # Voltear q3 para alinear con q1
    q3_flipped = q3[::-1, ::-1]
    if q1.shape != q3_flipped.shape:
        return 0.0

    norm1 = np.linalg.norm(q1)
    norm3 = np.linalg.norm(q3_flipped)

    if norm1 < 1e-15 or norm3 < 1e-15:
        return 0.0

    # Correlación normalizada
    correlation = float(np.sum(q1 * q3_flipped) / (norm1 * norm3))
    return round(max(0.0, min(1.0, correlation)), 4)


def _interpret(result: FrequencyResult) -> None:
    """Interpreta los hallazgos en lenguaje forense."""
    indicators = []

    # Pendiente espectral
    if result.spectral_slope is not None:
        if result.spectral_slope > -1.5:
            indicators.append(
                f"Pendiente espectral suave ({result.spectral_slope:.2f}, "
                f"esperado -2.0 a -3.0 en foto natural) — "
                f"déficit de alta frecuencia consistente con generación por IA"
            )
        elif result.spectral_slope < -3.5:
            indicators.append(
                f"Pendiente espectral pronunciada ({result.spectral_slope:.2f}) — "
                f"exceso de caída de alta frecuencia, posible sobre-suavizado"
            )

    # Ratio de alta frecuencia
    if result.high_freq_energy_ratio is not None:
        if result.high_freq_energy_ratio < 0.05:
            indicators.append(
                f"Baja energía en altas frecuencias ({result.high_freq_energy_ratio*100:.1f}% "
                f"del total) — las fotos reales tienen más ruido de sensor en altas frecuencias"
            )

    # Picos periódicos
    if result.periodic_peaks_detected > 2:
        indicators.append(
            f"{result.periodic_peaks_detected} picos periódicos detectados — "
            f"patrón repetitivo en el espectro, posible artefacto de red neuronal"
        )

    # Simetría excesiva
    if result.spectral_symmetry is not None and result.spectral_symmetry > 0.995:
        indicators.append(
            f"Simetría espectral excesiva ({result.spectral_symmetry:.4f}) — "
            f"escenas naturales producen espectros menos simétricos"
        )

    result.findings.extend(indicators)

    if len(indicators) >= 3:
        result.ai_relevant = "ALTA sospecha de IA generativa por perfil espectral"
        result.confidence = "MODERADA-ALTA — múltiples indicadores espectrales coinciden"
    elif len(indicators) >= 2:
        result.ai_relevant = "MODERADA sospecha — dos indicadores espectrales"
        result.confidence = "MODERADA — requiere cruce con otros análisis"
    elif len(indicators) >= 1:
        result.ai_relevant = "BAJA sospecha — un indicador no es concluyente"
        result.confidence = "BAJA — el indicador puede tener causas no-IA"
    else:
        result.ai_relevant = "Sin indicadores espectrales de IA"
        result.confidence = "Perfil espectral consistente con imagen no-IA"

    result.caveats.append(
        "La pendiente espectral varía con el contenido — cielo uniforme "
        "tiene pendiente distinta a vegetación detallada."
    )
    result.caveats.append(
        "La recompresión JPEG atenúa altas frecuencias — una foto real "
        "muy comprimida puede parecer espectralmente similar a IA."
    )


def analyze(image_source: str | Path | bytes) -> FrequencyResult:
    """
    Analiza el espectro de frecuencia de una imagen.

    Args:
        image_source: ruta de archivo, Path, o bytes crudos.

    Returns:
        FrequencyResult con perfil espectral, pendiente, picos, y
        hallazgos forenses.
    """
    result = FrequencyResult()

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
                f"espectral — mínimo {MIN_DIMENSION}x{MIN_DIMENSION}"
            )
            img.close()
            return result

        # Convertir a escala de grises (luminancia)
        gray = np.array(img.convert("L"), dtype=np.float64)
        img.close()

        # Espectro de potencia 2D
        power = _compute_power_spectrum(gray)

        # Perfil radial
        frequencies, energies = _radial_profile(power)

        if len(frequencies) < 5:
            result.applicable = False
            result.skip_reason = "Perfil radial insuficiente"
            return result

        # Pendiente espectral (log-log)
        slope, r_sq = _fit_spectral_slope(frequencies, energies)
        result.spectral_slope = slope
        result.slope_r_squared = r_sq

        # Ratio de energía alta/baja frecuencia
        mid = len(frequencies) // 2
        total_energy = float(np.sum(energies))
        if total_energy > 0:
            result.low_freq_energy_ratio = round(
                float(np.sum(energies[:mid])) / total_energy, 4
            )
            result.high_freq_energy_ratio = round(
                float(np.sum(energies[mid:])) / total_energy, 4
            )

        # Detección de picos periódicos
        peaks = _detect_peaks(frequencies, energies)
        result.periodic_peaks_detected = len(peaks)
        result.peak_frequencies = [round(p, 2) for p in peaks]

        # Simetría espectral
        result.spectral_symmetry = _compute_symmetry(power)

        _interpret(result)

    except Exception as e:
        result.applicable = False
        result.skip_reason = f"Error durante análisis de frecuencia: {str(e)[:200]}"
        logger.error("Frequency analysis error: %s", str(e))

    return result
