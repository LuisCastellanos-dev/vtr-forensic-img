"""
vtr-forensic-img v0.3.0
core/quantization_analyzer.py

Análisis de tablas de cuantización JPEG.

QUÉ DETECTA:
  Cada cámara digital y cada biblioteca de compresión JPEG usa tablas
  de cuantización distintas. Las tablas son observables directamente
  en los bytes del archivo (markers DQT, 0xFFDB) — no requieren
  interpretación subjetiva.

  - Cámaras reales: tablas específicas del fabricante, optimizadas
    para su sensor y procesador de imagen. Canon, Nikon, Samsung,
    Apple tienen tablas distintas y documentadas.
  - Generadores de IA: usan la biblioteca JPEG del framework de ML
    (típicamente Pillow/libjpeg, mozjpeg, o libjpeg-turbo). Las
    tablas son genéricas — no corresponden a ningún fabricante de
    cámara.
  - Editores: Photoshop, GIMP, Lightroom tienen tablas propias
    distintas de cámaras y de IA.

CÓMO FUNCIONA:
  1. Lee los markers DQT (0xFFDB) del archivo JPEG byte a byte
  2. Extrae las tablas de cuantización (luminancia y crominancia)
  3. Calcula la "calidad estimada" basada en la tabla de luminancia
  4. Compara contra firmas conocidas de bibliotecas de compresión
  5. Reporta si la tabla corresponde a una fuente conocida

LIMITACIONES HONESTAS:
  1. Las tablas conocidas cubren las bibliotecas más comunes, no
     todas las existentes. Una tabla desconocida no es evidencia
     de IA — puede ser un software menos común.
  2. Una imagen re-comprimida pierde la tabla original y adopta la
     del último software que la guardó.
  3. Las tablas son por calidad de compresión — la misma biblioteca
     produce tablas distintas a calidad 75 vs 95.
"""

from __future__ import annotations

import io
import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)


# ── Tablas de referencia conocidas ────────────────────────────────────────────
# Tabla de luminancia estándar IJG/libjpeg a calidad 75
# (base de la especificación JPEG, Annex K)
LIBJPEG_STANDARD_LUMINANCE_Q75 = [
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99,
]

# Firmas de bibliotecas conocidas por la primera fila de la tabla de luminancia
# (los primeros 8 valores son suficientes para fingerprinting)
KNOWN_SIGNATURES = {
    "IJG/libjpeg standard": (16, 11, 10, 16, 24, 40, 51, 61),
    "Photoshop (Save for Web)": (1, 1, 1, 1, 1, 1, 1, 1),  # calidad 100
}


@dataclass
class QuantizationTable:
    """Una tabla de cuantización extraída del JPEG."""
    table_id: int  # 0 = luminancia, 1 = crominancia
    precision: int  # 0 = 8-bit, 1 = 16-bit
    values: list[int] = field(default_factory=list)
    estimated_quality: int | None = None


@dataclass
class QuantizationResult:
    applicable: bool = True
    skip_reason: str = ""

    tables: list[QuantizationTable] = field(default_factory=list)
    num_tables: int = 0

    # Fingerprinting
    matches_known_library: str | None = None
    is_standard_table: bool = False
    estimated_quality: int | None = None

    # Indicadores forenses
    findings: list[str] = field(default_factory=list)
    ai_relevant: str = ""


def _estimate_quality(lum_table: list[int]) -> int:
    """
    Estima la calidad JPEG (1-100) a partir de la tabla de luminancia.

    Basado en el algoritmo inverso de IJG: compara la tabla observada
    contra la tabla estándar escalada a diferentes calidades hasta
    encontrar la más cercana.
    """
    if not lum_table or len(lum_table) < 64:
        return -1

    std = LIBJPEG_STANDARD_LUMINANCE_Q75
    best_quality = 50
    best_diff = float('inf')

    for q in range(1, 101):
        # Fórmula IJG para escalar la tabla estándar
        if q < 50:
            scale = 5000 // q
        else:
            scale = 200 - q * 2

        total_diff = 0
        for i in range(64):
            scaled = max(1, min(255, (std[i] * scale + 50) // 100))
            total_diff += abs(lum_table[i] - scaled)

        if total_diff < best_diff:
            best_diff = total_diff
            best_quality = q

    return best_quality


def _fingerprint_table(first_row: tuple) -> str | None:
    """Compara la primera fila de la tabla contra firmas conocidas."""
    for name, sig in KNOWN_SIGNATURES.items():
        if first_row == sig:
            return name
    return None


def _check_standard_scaling(lum_table: list[int]) -> bool:
    """
    Verifica si la tabla sigue el patrón de escalado estándar de IJG.

    Las cámaras reales típicamente usan tablas optimizadas que NO
    siguen el escalado estándar. Las bibliotecas de software (Pillow,
    libjpeg, mozjpeg) SÍ siguen el escalado estándar porque usan
    la implementación de referencia.

    Una tabla que sigue el escalado estándar es consistente con
    software de procesamiento, no con captura de cámara.
    """
    if not lum_table or len(lum_table) < 64:
        return False

    std = LIBJPEG_STANDARD_LUMINANCE_Q75
    quality = _estimate_quality(lum_table)

    if quality < 50:
        scale = 5000 // quality
    else:
        scale = 200 - quality * 2

    # Comparar la tabla observada contra la estándar escalada
    max_diff = 0
    for i in range(64):
        scaled = max(1, min(255, (std[i] * scale + 50) // 100))
        max_diff = max(max_diff, abs(lum_table[i] - scaled))

    # Si la diferencia máxima es <= 1, la tabla sigue el escalado estándar
    return max_diff <= 1


def _parse_dqt_markers(data: bytes) -> list[QuantizationTable]:
    """
    Extrae tablas de cuantización de los markers DQT (0xFFDB) del JPEG.

    Lee byte a byte — no usa Pillow ni exifread, porque queremos
    los bytes exactos del archivo para la cadena de custodia.
    """
    tables = []
    pos = 0

    while pos < len(data) - 1:
        # Buscar marker 0xFF
        if data[pos] != 0xFF:
            pos += 1
            continue

        marker = data[pos + 1]

        # SOI (0xD8) y EOI (0xD9) no tienen longitud
        if marker in (0xD8, 0xD9, 0x00):
            pos += 2
            continue

        # SOS (0xDA) — después de esto viene el scan data, dejar de buscar
        if marker == 0xDA:
            break

        # Leer longitud del segmento
        if pos + 3 >= len(data):
            break

        seg_length = struct.unpack('>H', data[pos + 2:pos + 4])[0]

        # DQT marker (0xDB)
        if marker == 0xDB:
            seg_data = data[pos + 4:pos + 2 + seg_length]
            offset = 0

            while offset < len(seg_data):
                if offset >= len(seg_data):
                    break

                info_byte = seg_data[offset]
                precision = (info_byte >> 4) & 0x0F  # 0 = 8-bit, 1 = 16-bit
                table_id = info_byte & 0x0F
                offset += 1

                value_size = 2 if precision == 1 else 1
                num_values = 64
                values = []

                for _ in range(num_values):
                    if offset >= len(seg_data):
                        break
                    if precision == 1:
                        if offset + 1 >= len(seg_data):
                            break
                        val = struct.unpack('>H', seg_data[offset:offset + 2])[0]
                        offset += 2
                    else:
                        val = seg_data[offset]
                        offset += 1
                    values.append(val)

                if len(values) == 64:
                    qt = QuantizationTable(
                        table_id=table_id,
                        precision=precision,
                        values=values,
                    )
                    qt.estimated_quality = _estimate_quality(values) if table_id == 0 else None
                    tables.append(qt)

        pos += 2 + seg_length

    return tables


def analyze(image_source: str | Path | bytes) -> QuantizationResult:
    """
    Analiza las tablas de cuantización de un archivo JPEG.

    Args:
        image_source: ruta de archivo, Path, o bytes crudos.

    Returns:
        QuantizationResult con las tablas extraídas, fingerprinting,
        y hallazgos forenses.
    """
    result = QuantizationResult()

    try:
        if isinstance(image_source, (str, Path)):
            path = Path(image_source)
            if not path.exists():
                result.applicable = False
                result.skip_reason = f"archivo no encontrado: {image_source}"
                return result
            data = path.read_bytes()
        elif isinstance(image_source, bytes):
            data = image_source
        else:
            result.applicable = False
            result.skip_reason = f"Tipo no soportado: {type(image_source)}"
            return result

        # Verificar que es JPEG (SOI marker)
        if len(data) < 2 or data[0:2] != b'\xFF\xD8':
            result.applicable = False
            result.skip_reason = "No es un archivo JPEG (sin marker SOI 0xFFD8)"
            return result

        # Extraer tablas DQT
        tables = _parse_dqt_markers(data)
        result.tables = tables
        result.num_tables = len(tables)

        if not tables:
            result.applicable = False
            result.skip_reason = "No se encontraron tablas de cuantización (DQT)"
            return result

        # Tabla de luminancia (ID 0) — la más informativa
        lum_tables = [t for t in tables if t.table_id == 0]
        if lum_tables:
            lum = lum_tables[0]
            result.estimated_quality = lum.estimated_quality

            # Fingerprinting contra firmas conocidas
            first_row = tuple(lum.values[:8])
            match = _fingerprint_table(first_row)
            if match:
                result.matches_known_library = match
                result.findings.append(
                    f"Tabla de luminancia coincide con: {match}"
                )

            # Verificar si sigue escalado estándar IJG
            is_standard = _check_standard_scaling(lum.values)
            result.is_standard_table = is_standard

            if is_standard:
                result.findings.append(
                    "La tabla sigue el escalado estándar IJG/libjpeg — "
                    "consistente con software de procesamiento "
                    "(Pillow, libjpeg, mozjpeg), no con captura de cámara. "
                    "Las cámaras reales usan tablas optimizadas específicas "
                    "del fabricante que difieren del estándar."
                )
                result.ai_relevant = (
                    "CONSISTENTE CON SOFTWARE — la tabla de cuantización "
                    "sigue el escalado estándar IJG, típico de bibliotecas "
                    "de procesamiento de imagen (incluyendo las que usan "
                    "los generadores de IA). No es concluyente por sí solo — "
                    "también ocurre en imágenes re-guardadas con Pillow, "
                    "GIMP, o cualquier software basado en libjpeg."
                )
            else:
                result.findings.append(
                    "La tabla NO sigue el escalado estándar IJG — "
                    "consistente con tabla optimizada de fabricante de cámara "
                    "o software especializado."
                )
                result.ai_relevant = (
                    "CONSISTENTE CON CÁMARA — la tabla de cuantización "
                    "no sigue el patrón estándar IJG, lo que sugiere "
                    "tablas optimizadas de un fabricante de cámara o "
                    "software especializado de procesamiento."
                )

            # Calidad estimada
            if result.estimated_quality is not None:
                result.findings.append(
                    f"Calidad JPEG estimada: {result.estimated_quality}% "
                    f"(basado en comparación con tabla IJG escalada)"
                )

        # Tabla de crominancia (ID 1) — complementaria
        chrom_tables = [t for t in tables if t.table_id == 1]
        if chrom_tables:
            result.findings.append(
                f"Tabla de crominancia presente (ID {chrom_tables[0].table_id})"
            )

        # Observación sobre número de tablas
        if len(tables) == 1:
            result.findings.append(
                "Solo 1 tabla de cuantización — inusual para JPEG con color "
                "(típicamente 2: luminancia + crominancia). Puede indicar "
                "imagen en escala de grises o procesamiento no estándar."
            )
        elif len(tables) > 2:
            result.findings.append(
                f"{len(tables)} tablas de cuantización — inusual "
                f"(típicamente 2). Puede indicar procesamiento multi-paso."
            )

    except Exception as e:
        result.applicable = False
        result.skip_reason = f"Error durante análisis de cuantización: {str(e)[:200]}"
        logger.error("Quantization analysis error: %s", str(e))

    return result
