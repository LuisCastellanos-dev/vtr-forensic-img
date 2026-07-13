"""
vtr-forensic-img v0.2.0
core/entropy_analyzer.py

Análisis de entropía de Shannon por bloques.

QUÉ DETECTA (complementa ELA, no lo duplica):
  ELA detecta diferencias en nivel de compresión JPEG (lossy artifacts).
  La entropía de Shannon detecta aleatoriedad de bits — son señales
  distintas y complementarias:

  - Entropía baja anómala: región clonada/copiada con poca variación
    respecto al bloque original — sospecha de copy-paste.
  - Entropía alta anómala: datos cifrados, comprimidos, o steganográficos
    insertados en la imagen — los datos cifrados tienen entropía
    cercana a 8.0 bits/byte (máximo teórico).
  - Cambio abrupto de entropía entre bloques adyacentes: frontera de
    edición donde una región fue reemplazada por otra con
    características estadísticas distintas.

CÓMO FUNCIONA:
  1. La imagen se divide en bloques de tamaño configurable (default 64px).
  2. Para cada bloque, se calcula la entropía de Shannon sobre los bytes
     crudos (no sobre los píxeles como valores de color, sino sobre la
     distribución de bytes del bloque serializado).
  3. Se calcula la entropía global de la imagen como referencia.
  4. Los bloques cuya entropía se desvía significativamente de la media
     (por encima de un umbral configurable en desviaciones estándar)
     se marcan como anómalos.

LIMITACIONES HONESTAS:
  1. La entropía por sí sola no distingue "editado" de "contenido
     naturalmente distinto" — una imagen con cielo uniforme (baja
     entropía) y árboles detallados (alta entropía) tendrá variación
     natural. El indicador es la distribución de la variación, no su
     existencia.
  2. Una imagen recomprimida múltiples veces puede tener entropía
     uniforme sin ser auténtica — la recompresión homogeniza la
     distribución.
  3. El tamaño de bloque afecta la sensibilidad: bloques más pequeños
     detectan ediciones más finas pero producen más falsos positivos.

REFERENCIA:
  Shannon, C.E. (1948). "A Mathematical Theory of Communication".
  Bell System Technical Journal, 27(3), 379–423.
  La entropía de Shannon es el fundamento teórico — la aplicación
  forense a imágenes es práctica de la industria documentada en
  múltiples herramientas de análisis forense digital.
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

DEFAULT_BLOCK_SIZE = 64
DEFAULT_STD_THRESHOLD = 2.0  # desviaciones estándar sobre/bajo la media
MAX_IMAGE_PIXELS = 50 * 1024 * 1024


@dataclass
class EntropyBlock:
    """Un bloque con su valor de entropía y posición."""
    x: int
    y: int
    width: int
    height: int
    entropy: float
    deviation_from_mean: float  # en desviaciones estándar
    anomaly_type: str = ""  # "HIGH" / "LOW" / ""


@dataclass
class EntropyResult:
    applicable: bool = True
    skip_reason: str = ""

    block_size_used: int = DEFAULT_BLOCK_SIZE
    std_threshold_used: float = DEFAULT_STD_THRESHOLD

    global_entropy: float = 0.0
    block_mean_entropy: float = 0.0
    block_std_entropy: float = 0.0
    block_min_entropy: float = 0.0
    block_max_entropy: float = 0.0
    total_blocks: int = 0

    anomalous_blocks_high: int = 0
    anomalous_blocks_low: int = 0
    anomalous_ratio: float = 0.0

    top_anomalies: list[EntropyBlock] = field(default_factory=list)

    interpretation: str = ""
    confidence: str = ""
    caveats: list[str] = field(default_factory=list)


def _shannon_entropy(data: bytes) -> float:
    """
    Entropía de Shannon en bits/byte sobre una secuencia de bytes.
    Rango: 0.0 (todos los bytes iguales) a 8.0 (distribución uniforme
    perfecta, como datos cifrados o aleatorios puros).
    """
    if not data:
        return 0.0

    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1

    length = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


def _interpret(result: EntropyResult) -> None:
    """Interpreta los números en lenguaje forense."""
    ratio = result.anomalous_ratio
    high = result.anomalous_blocks_high
    low = result.anomalous_blocks_low
    global_e = result.global_entropy
    std = result.block_std_entropy

    # Entropía global muy alta (cercana a 8.0): posible dato cifrado/aleatorio
    if global_e > 7.8:
        result.interpretation = (
            f"Entropía global extremadamente alta ({global_e:.3f} / 8.0 máx). "
            f"Esto es consistente con datos cifrados, comprimidos, o "
            f"aleatorios puros — no con una imagen fotográfica típica. "
            f"Verificar si el archivo es realmente una imagen y no datos "
            f"binarios con extensión de imagen."
        )
        result.confidence = "ALTA sospecha de contenido no-imagen o datos ocultos"
        return

    if ratio < 0.03 and std < 0.5:
        result.interpretation = (
            f"Distribución de entropía uniforme ({result.block_mean_entropy:.2f} ± "
            f"{std:.3f} bits/byte). Sin cambios abruptos entre bloques — "
            f"consistente con imagen sin edición localizada."
        )
        result.confidence = "BAJA sospecha de manipulación por entropía"

    elif ratio < 0.10:
        result.interpretation = (
            f"Anomalías menores: {high} bloques con entropía alta anómala, "
            f"{low} con entropía baja anómala ({ratio*100:.1f}% del total). "
            f"Puede indicar edición localizada o variación natural del "
            f"contenido de la imagen."
        )
        result.confidence = "INDETERMINADO — requiere contexto visual"

    else:
        result.interpretation = (
            f"Anomalías significativas: {ratio*100:.1f}% de bloques con "
            f"entropía fuera del rango normal. {high} bloques de alta "
            f"entropía (posibles datos insertados), {low} de baja entropía "
            f"(posibles regiones clonadas/uniformes). La distribución no "
            f"es consistente con una imagen capturada sin modificar."
        )
        result.confidence = "MODERADA-ALTA sospecha de manipulación por entropía"

    result.caveats.append(
        f"Tamaño de bloque: {result.block_size_used}px. "
        f"Umbral: {result.std_threshold_used} desviaciones estándar. "
        f"Resultados distintos pueden obtenerse con otros parámetros."
    )
    result.caveats.append(
        "La entropía no distingue contenido editado de contenido "
        "naturalmente variable — una imagen con cielo (baja entropía) "
        "y vegetación (alta entropía) tendrá variación natural."
    )


def analyze(
    image_source: str | Path | bytes,
    block_size: int = DEFAULT_BLOCK_SIZE,
    std_threshold: float = DEFAULT_STD_THRESHOLD,
    max_anomalies_reported: int = 20,
) -> EntropyResult:
    """
    Analiza la entropía de Shannon por bloques de una imagen.

    Args:
        image_source: ruta de archivo, Path, o bytes crudos.
        block_size: tamaño de bloque en píxeles (default 64).
        std_threshold: cuántas desviaciones estándar sobre/bajo la media
            para marcar un bloque como anómalo (default 2.0).
        max_anomalies_reported: máximo de bloques anómalos en el output
            (los más extremos, ordenados por desviación).

    Returns:
        EntropyResult con estadísticas y bloques anómalos.
    """
    result = EntropyResult(
        block_size_used=block_size,
        std_threshold_used=std_threshold,
    )

    try:
        if isinstance(image_source, (str, Path)):
            img = Image.open(image_source)
        elif isinstance(image_source, bytes):
            img = Image.open(io.BytesIO(image_source))
        else:
            result.applicable = False
            result.skip_reason = f"Tipo no soportado: {type(image_source)}"
            return result

        w, h = img.size
        if w * h > MAX_IMAGE_PIXELS:
            result.applicable = False
            result.skip_reason = (
                f"Imagen demasiado grande ({w}x{h} = {w*h:,} px)"
            )
            img.close()
            return result

        img_rgb = img.convert("RGB")
        img.close()
        raw_bytes = img_rgb.tobytes()

        # Entropía global del archivo completo
        result.global_entropy = round(_shannon_entropy(raw_bytes), 4)

        # Dividir en bloques y calcular entropía por bloque
        arr = np.frombuffer(raw_bytes, dtype=np.uint8).reshape((h, w, 3))
        block_entropies = []
        block_coords = []

        for y in range(0, h - block_size + 1, block_size):
            for x in range(0, w - block_size + 1, block_size):
                block = arr[y:y + block_size, x:x + block_size]
                block_bytes = block.tobytes()
                e = _shannon_entropy(block_bytes)
                block_entropies.append(e)
                block_coords.append((x, y))

        if not block_entropies:
            result.applicable = False
            result.skip_reason = "Imagen demasiado pequeña para el tamaño de bloque"
            return result

        entropies = np.array(block_entropies)
        result.total_blocks = len(entropies)
        result.block_mean_entropy = round(float(np.mean(entropies)), 4)
        result.block_std_entropy = round(float(np.std(entropies)), 4)
        result.block_min_entropy = round(float(np.min(entropies)), 4)
        result.block_max_entropy = round(float(np.max(entropies)), 4)

        # Detectar anomalías
        mean = result.block_mean_entropy
        std = result.block_std_entropy
        anomalies = []

        if std > 0.001:  # evitar división por cero con imagen perfectamente uniforme
            for i, e in enumerate(block_entropies):
                deviation = (e - mean) / std
                if abs(deviation) > std_threshold:
                    x, y = block_coords[i]
                    atype = "HIGH" if deviation > 0 else "LOW"
                    anomalies.append(EntropyBlock(
                        x=x, y=y,
                        width=min(block_size, w - x),
                        height=min(block_size, h - y),
                        entropy=round(e, 4),
                        deviation_from_mean=round(deviation, 2),
                        anomaly_type=atype,
                    ))

        result.anomalous_blocks_high = sum(1 for a in anomalies if a.anomaly_type == "HIGH")
        result.anomalous_blocks_low = sum(1 for a in anomalies if a.anomaly_type == "LOW")
        result.anomalous_ratio = round(
            (result.anomalous_blocks_high + result.anomalous_blocks_low) / max(result.total_blocks, 1),
            4
        )

        # Ordenar por desviación más extrema y limitar
        anomalies.sort(key=lambda a: abs(a.deviation_from_mean), reverse=True)
        result.top_anomalies = anomalies[:max_anomalies_reported]

        _interpret(result)

    except Exception as e:
        result.applicable = False
        result.skip_reason = f"Error durante análisis de entropía: {str(e)[:200]}"
        logger.error("Entropy analysis error: %s", str(e))

    return result
