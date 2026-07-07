"""
vtr-forensic-img v0.1.0
core/ela_analyzer.py

Error Level Analysis (ELA) para detección de manipulación de imagen.

CÓMO FUNCIONA ELA:
  Una imagen JPEG se recomprime a una calidad fija conocida (ej. 95%).
  En una imagen no manipulada, todas las regiones tienen niveles de
  error de recompresión similares — la imagen entera fue comprimida
  bajo el mismo esquema original. En una imagen manipulada, las
  regiones que fueron editadas/pegadas con posterioridad muestran un
  nivel de error distinto al fondo, porque ya habían sido comprimidas
  una vez antes con un esquema diferente.

LIMITACIONES HONESTAS (documentadas, no ocultas):
  1. ELA es un indicador, no una prueba. Un positivo no confirma
     manipulación; un negativo no la descarta.
  2. Múltiples recompresiones de la misma imagen sin edición pueden
     producir regiones de error desigual — la imagen puede haber
     pasado por WhatsApp, redes sociales, o conversiones de formato
     que recomprimen sin editar.
  3. El umbral de "anomalía significativa" es configurable — valores
     diferentes producen resultados diferentes. El valor por defecto
     (15.0) es conservador; el reporte incluye el umbral usado para
     que el auditor pueda reproducir el análisis con otros valores.
  4. Las imágenes PNG de origen no son nativamente vulnerables al
     mismo análisis (no tienen compresión lossy) — se aplica ELA
     solo tras convertir a JPEG, lo cual introduce un paso extra.

REFERENCIA ACADÉMICA: Neal Krawetz, "A Picture's Worth", Hacker
Factor Blog, 2007. Los fundamentos del método son de dominio público
y han sido replicados y validados independientemente.
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

DEFAULT_ELA_QUALITY = 95
DEFAULT_ANOMALY_THRESHOLD = 15.0
MAX_IMAGE_PIXELS = 50 * 1024 * 1024  # 50 megapixels — límite de seguridad


@dataclass
class ELARegion:
    """Una región con nivel de error anómalo."""
    x: int
    y: int
    width: int
    height: int
    mean_error: float
    description: str


@dataclass
class ELAResult:
    """Resultado completo de un análisis ELA."""
    applicable: bool = True
    skip_reason: str = ""
    ela_quality_used: int = DEFAULT_ELA_QUALITY
    threshold_used: float = DEFAULT_ANOMALY_THRESHOLD

    global_mean_error: float = 0.0
    global_max_error: float = 0.0
    global_std_error: float = 0.0

    anomalous_pixel_ratio: float = 0.0
    anomalous_regions: list[ELARegion] = field(default_factory=list)

    interpretation: str = ""
    confidence: str = ""
    caveats: list[str] = field(default_factory=list)

    ela_image_bytes: bytes | None = None


def _pixels_to_ela_array(original: Image.Image, quality: int) -> np.ndarray:
    """
    Recomprime la imagen al quality dado y calcula la diferencia absoluta
    pixel a pixel — el "mapa de error" del ELA.
    """
    original_rgb = original.convert('RGB')

    buffer = io.BytesIO()
    original_rgb.save(buffer, format='JPEG', quality=quality)
    buffer.seek(0)
    recompressed = Image.open(buffer).convert('RGB')

    orig_array = np.array(original_rgb, dtype=np.float32)
    recomp_array = np.array(recompressed, dtype=np.float32)

    diff = np.abs(orig_array - recomp_array)
    return diff


def _find_anomalous_regions(
    ela_array: np.ndarray,
    threshold: float,
    block_size: int = 64,
) -> list[ELARegion]:
    """
    Divide la imagen en bloques y encuentra los que tienen error
    promedio por encima del umbral — heurística simple pero
    reproducible, que un auditor puede verificar manualmente.
    """
    h, w = ela_array.shape[:2]
    regions = []

    for y in range(0, h - block_size + 1, block_size):
        for x in range(0, w - block_size + 1, block_size):
            block = ela_array[y:y + block_size, x:x + block_size]
            mean_error = float(np.mean(block))

            if mean_error > threshold:
                regions.append(ELARegion(
                    x=x, y=y,
                    width=min(block_size, w - x),
                    height=min(block_size, h - y),
                    mean_error=round(mean_error, 2),
                    description=f"Error promedio {mean_error:.1f} > umbral {threshold}"
                ))

    return sorted(regions, key=lambda r: r.mean_error, reverse=True)


def _render_ela_image(ela_array: np.ndarray) -> bytes:
    """
    Genera la imagen ELA amplificada para visualización — los errores
    se escalan para que sean visibles en el reporte. El factor de
    amplificación es estándar (x10) y está documentado aquí para
    reproducibilidad.
    """
    amplified = np.clip(ela_array * 10, 0, 255).astype(np.uint8)
    ela_img = Image.fromarray(amplified, mode='RGB')
    buffer = io.BytesIO()
    ela_img.save(buffer, format='PNG')
    return buffer.getvalue()


def _interpret(result: ELAResult) -> None:
    """
    Interpreta los números en lenguaje forense directo —
    sin hipérbole ni eufemismo, con los caveats correspondientes.
    """
    ratio = result.anomalous_pixel_ratio
    std = result.global_std_error
    mean = result.global_mean_error

    if ratio < 0.02 and std < 5.0:
        result.interpretation = (
            "Sin anomalías significativas de compresión. El nivel de error "
            "es uniforme en toda la imagen, consistente con una imagen sin "
            "ediciones localizadas post-captura."
        )
        result.confidence = "BAJA sospecha de manipulación por ELA"

    elif ratio < 0.10 and std < 15.0:
        result.interpretation = (
            "Anomalías menores detectadas. Algunas regiones muestran niveles "
            "de error ligeramente distintos al fondo. Esto puede indicar "
            "edición localizada, o puede ser resultado de recompresiones "
            "previas sin edición (redes sociales, conversión de formato)."
        )
        result.confidence = "INDETERMINADO — requiere análisis adicional"
        result.caveats.append(
            "Un nivel de error moderado no distingue entre edición real y "
            "recompresión inocente — se necesita contexto adicional sobre "
            "el historial del archivo."
        )

    else:
        result.interpretation = (
            f"Anomalías significativas: {ratio*100:.1f}% de los bloques "
            f"supera el umbral de error (media global: {mean:.1f}, "
            f"desviación estándar: {std:.1f}). Las regiones marcadas en "
            f"la imagen ELA merecen revisión manual — la distribución de "
            f"error es inconsistente con una imagen capturada o comprimida "
            f"una sola vez."
        )
        result.confidence = "MODERADA-ALTA sospecha de manipulación por ELA"
        result.caveats.append(
            "ELA es un indicador, no una prueba. Este resultado no confirma "
            "manipulación — confirma que la distribución de compresión es "
            "anómala. El auditor debe corroborar con otros indicadores "
            "(metadata, análisis estegonográfico, fuente original)."
        )

    result.caveats.append(
        f"Umbral usado: {result.threshold_used} (escala 0-255). "
        f"Calidad de recompresión: {result.ela_quality_used}%. "
        f"Resultados distintos pueden obtenerse con otros parámetros."
    )


def analyze(
    image_source: str | Path | bytes,
    quality: int = DEFAULT_ELA_QUALITY,
    threshold: float = DEFAULT_ANOMALY_THRESHOLD,
    include_ela_image: bool = True,
) -> ELAResult:
    """
    Realiza ELA sobre una imagen.

    Args:
        image_source: ruta de archivo, objeto Path, o bytes crudos de imagen.
        quality: calidad JPEG de recompresión (1-95). 95 es el estándar
            de la literatura. Cambiar este valor cambia los resultados —
            siempre se registra en el output.
        threshold: umbral de error promedio por bloque (escala 0-255)
            para marcar una región como anómala.
        include_ela_image: si True, incluye la imagen ELA amplificada
            como bytes PNG en el resultado (para visualización en reporte).

    Returns:
        ELAResult con todos los indicadores y la interpretación forense.
    """
    result = ELAResult(ela_quality_used=quality, threshold_used=threshold)

    try:
        if isinstance(image_source, (str, Path)):
            img = Image.open(image_source)
        elif isinstance(image_source, bytes):
            img = Image.open(io.BytesIO(image_source))
        else:
            result.applicable = False
            result.skip_reason = f"Tipo de fuente no soportado: {type(image_source)}"
            return result

        # Seguridad: limitar el tamaño máximo de imagen procesada
        w, h = img.size
        if w * h > MAX_IMAGE_PIXELS:
            result.applicable = False
            result.skip_reason = (
                f"Imagen demasiado grande para ELA ({w}x{h} = {w*h:,} px, "
                f"máximo {MAX_IMAGE_PIXELS:,} px). Redimensionar antes de analizar."
            )
            img.close()
            return result

        # ELA solo es significativo para imágenes con compresión lossy (JPEG)
        # Para PNG y otros formatos lossless, el análisis sigue siendo
        # posible (convirtiendo a JPEG primero) pero se añade un caveat.
        original_format = getattr(img, 'format', None)
        if original_format not in ('JPEG', 'JPEG2000', 'WEBP'):
            result.caveats.append(
                f"Formato original: {original_format}. ELA se aplica tras "
                f"conversión interna a JPEG — este paso extra puede introducir "
                f"artefactos propios. Los resultados son menos concluyentes "
                f"que en imágenes JPEG nativas."
            )

        ela_array = _pixels_to_ela_array(img, quality)
        img.close()

        result.global_mean_error = round(float(np.mean(ela_array)), 3)
        result.global_max_error = round(float(np.max(ela_array)), 3)
        result.global_std_error = round(float(np.std(ela_array)), 3)

        total_pixels = ela_array.shape[0] * ela_array.shape[1]
        anomalous_pixels = int(np.sum(np.mean(ela_array, axis=2) > threshold))
        result.anomalous_pixel_ratio = round(anomalous_pixels / total_pixels, 4)

        result.anomalous_regions = _find_anomalous_regions(ela_array, threshold)

        if include_ela_image:
            result.ela_image_bytes = _render_ela_image(ela_array)

        _interpret(result)

    except Exception as e:
        result.applicable = False
        result.skip_reason = f"Error durante ELA: {str(e)[:200]}"
        logger.error("ELA error: %s", str(e))

    return result
