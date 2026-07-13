"""
vtr-forensic-img v0.2.0
core/diff_analyzer.py

Comparación diferencial entre dos imágenes provistas por el analista.

PROPÓSITO:
  Responder la pregunta "¿estas dos imágenes son idénticas? ¿dónde
  difieren exactamente?" — a nivel de bytes, metadata, y estructura,
  no solo a nivel de píxeles.

DECISIÓN ARQUITECTÓNICA (documentada, no asumida):
  Este módulo nunca asume la existencia de una "imagen dorada" o
  "verdad de fábrica" externa. El analista provee ambas imágenes
  explícitamente — si no existe una versión original verificable,
  la comparación no se puede hacer, y el sistema lo dice claramente
  en vez de inventar un referente.

  La terminología deliberada es "imagen A" e "imagen B" — no
  "original" y "sospechosa", porque el módulo no sabe cuál es cuál.
  El analista asigna ese significado según su contexto.

TRES NIVELES DE COMPARACIÓN:
  1. Binario: ¿los bytes son idénticos? Si no, ¿en qué offset difieren?
  2. Metadata: ¿los campos EXIF/XMP difieren? ¿cuáles y cómo?
  3. Visual: ¿los píxeles difieren? ¿en qué regiones y por cuánto?
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from PIL import Image

from .metadata_extractor import extract, ImageMetadata

logger = logging.getLogger(__name__)


@dataclass
class BinaryDiff:
    """Resultado de comparación a nivel de bytes crudos."""
    identical: bool = False
    size_a: int = 0
    size_b: int = 0
    sha256_a: str = ""
    sha256_b: str = ""
    first_diff_offset: int | None = None
    total_diff_bytes: int = 0
    size_difference: int = 0


@dataclass
class MetadataFieldDiff:
    """Un campo de metadata que difiere entre A y B."""
    field_name: str
    value_a: str | None  # None = ausente en A
    value_b: str | None  # None = ausente en B
    diff_type: str  # "changed" / "added_in_b" / "removed_in_b"


@dataclass
class MetadataDiff:
    """Resultado de comparación de metadata."""
    total_fields_a: int = 0
    total_fields_b: int = 0
    fields_identical: int = 0
    fields_different: int = 0
    fields_only_in_a: int = 0
    fields_only_in_b: int = 0
    differences: list[MetadataFieldDiff] = field(default_factory=list)


@dataclass
class VisualDiff:
    """Resultado de comparación a nivel de píxeles."""
    applicable: bool = True
    skip_reason: str = ""
    dimensions_match: bool = False
    dimensions_a: tuple[int, int] | None = None
    dimensions_b: tuple[int, int] | None = None
    pixels_identical: bool = False
    total_pixels: int = 0
    diff_pixels: int = 0
    diff_ratio: float = 0.0
    mean_pixel_diff: float = 0.0
    max_pixel_diff: float = 0.0


@dataclass
class DiffResult:
    """Resultado completo de comparación diferencial."""
    image_a: str = ""
    image_b: str = ""
    binary: BinaryDiff = field(default_factory=BinaryDiff)
    metadata: MetadataDiff = field(default_factory=MetadataDiff)
    visual: VisualDiff = field(default_factory=VisualDiff)
    summary: str = ""
    error: str | None = None


def _compute_sha256(path: Path) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _compare_binary(path_a: Path, path_b: Path) -> BinaryDiff:
    """Comparación byte a byte de dos archivos."""
    result = BinaryDiff()
    result.size_a = path_a.stat().st_size
    result.size_b = path_b.stat().st_size
    result.size_difference = result.size_b - result.size_a
    result.sha256_a = _compute_sha256(path_a)
    result.sha256_b = _compute_sha256(path_b)

    if result.sha256_a == result.sha256_b:
        result.identical = True
        return result

    # Encontrar la primera diferencia y contar bytes distintos
    with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
        offset = 0
        first_found = False
        diff_count = 0

        while True:
            chunk_a = fa.read(4096)
            chunk_b = fb.read(4096)

            if not chunk_a and not chunk_b:
                break

            # Comparar byte a byte dentro del chunk
            min_len = min(len(chunk_a), len(chunk_b))
            for i in range(min_len):
                if chunk_a[i] != chunk_b[i]:
                    diff_count += 1
                    if not first_found:
                        result.first_diff_offset = offset + i
                        first_found = True

            # Bytes sobrantes en el archivo más largo
            if len(chunk_a) != len(chunk_b):
                diff_count += abs(len(chunk_a) - len(chunk_b))
                if not first_found:
                    result.first_diff_offset = offset + min_len
                    first_found = True

            offset += max(len(chunk_a), len(chunk_b))

    result.total_diff_bytes = diff_count
    return result


def _compare_metadata(meta_a: ImageMetadata, meta_b: ImageMetadata) -> MetadataDiff:
    """Comparación campo a campo de metadata EXIF."""
    result = MetadataDiff()

    fields_a = meta_a.raw_exif_fields
    fields_b = meta_b.raw_exif_fields
    result.total_fields_a = len(fields_a)
    result.total_fields_b = len(fields_b)

    all_keys = set(fields_a.keys()) | set(fields_b.keys())

    for key in sorted(all_keys):
        val_a = fields_a.get(key)
        val_b = fields_b.get(key)

        if val_a == val_b:
            result.fields_identical += 1
            continue

        if val_a is None:
            result.fields_only_in_b += 1
            result.differences.append(MetadataFieldDiff(
                field_name=key,
                value_a=None,
                value_b=val_b,
                diff_type="added_in_b",
            ))
        elif val_b is None:
            result.fields_only_in_a += 1
            result.differences.append(MetadataFieldDiff(
                field_name=key,
                value_a=val_a,
                value_b=None,
                diff_type="removed_in_b",
            ))
        else:
            result.fields_different += 1
            result.differences.append(MetadataFieldDiff(
                field_name=key,
                value_a=val_a,
                value_b=val_b,
                diff_type="changed",
            ))

    # Comparar también PNG text chunks
    chunks_a = meta_a.png_text_chunks
    chunks_b = meta_b.png_text_chunks
    all_chunk_keys = set(chunks_a.keys()) | set(chunks_b.keys())

    for key in sorted(all_chunk_keys):
        val_a = chunks_a.get(key)
        val_b = chunks_b.get(key)
        if val_a == val_b:
            result.fields_identical += 1
            continue

        diff_type = "changed"
        if val_a is None:
            diff_type = "added_in_b"
            result.fields_only_in_b += 1
        elif val_b is None:
            diff_type = "removed_in_b"
            result.fields_only_in_a += 1
        else:
            result.fields_different += 1

        result.differences.append(MetadataFieldDiff(
            field_name=f"PNG/{key}",
            value_a=val_a,
            value_b=val_b,
            diff_type=diff_type,
        ))

    return result


def _compare_visual(path_a: Path, path_b: Path) -> VisualDiff:
    """Comparación a nivel de píxeles."""
    result = VisualDiff()

    try:
        img_a = Image.open(path_a).convert("RGB")
        img_b = Image.open(path_b).convert("RGB")
    except Exception as e:
        result.applicable = False
        result.skip_reason = f"No se pudo abrir una o ambas imágenes: {str(e)[:100]}"
        return result

    result.dimensions_a = img_a.size
    result.dimensions_b = img_b.size
    result.dimensions_match = img_a.size == img_b.size

    if not result.dimensions_match:
        result.applicable = True
        result.skip_reason = (
            f"Dimensiones distintas ({img_a.size} vs {img_b.size}) — "
            f"comparación pixel a pixel no es significativa sin redimensionar, "
            f"y redimensionar alteraría la información forense."
        )
        result.pixels_identical = False
        img_a.close()
        img_b.close()
        return result

    arr_a = np.array(img_a, dtype=np.float32)
    arr_b = np.array(img_b, dtype=np.float32)
    img_a.close()
    img_b.close()

    diff = np.abs(arr_a - arr_b)
    result.total_pixels = arr_a.shape[0] * arr_a.shape[1]

    # Un píxel "difiere" si alguno de sus 3 canales RGB difiere
    pixel_diffs = np.any(diff > 0, axis=2)
    result.diff_pixels = int(np.sum(pixel_diffs))
    result.diff_ratio = round(result.diff_pixels / max(result.total_pixels, 1), 6)
    result.pixels_identical = result.diff_pixels == 0
    result.mean_pixel_diff = round(float(np.mean(diff)), 4)
    result.max_pixel_diff = round(float(np.max(diff)), 4)

    return result


def _build_summary(result: DiffResult) -> None:
    """Construye un resumen en lenguaje claro."""
    lines = []

    if result.binary.identical:
        lines.append(
            "Las dos imágenes son IDÉNTICAS a nivel binario — "
            "mismo SHA-256, mismos bytes exactos. No hay diferencia "
            "que analizar."
        )
        result.summary = " ".join(lines)
        return

    lines.append(
        f"Las imágenes son DISTINTAS (SHA-256 A: {result.binary.sha256_a[:16]}... "
        f"vs B: {result.binary.sha256_b[:16]}...)."
    )

    if result.binary.size_difference != 0:
        direction = "más grande" if result.binary.size_difference > 0 else "más pequeña"
        lines.append(
            f"B es {abs(result.binary.size_difference)} bytes {direction} que A."
        )

    if result.binary.first_diff_offset is not None:
        lines.append(
            f"Primera diferencia en offset 0x{result.binary.first_diff_offset:X} "
            f"({result.binary.total_diff_bytes:,} bytes distintos en total)."
        )

    md = result.metadata
    if md.fields_different > 0 or md.fields_only_in_a > 0 or md.fields_only_in_b > 0:
        lines.append(
            f"Metadata: {md.fields_different} campos cambiados, "
            f"{md.fields_only_in_a} solo en A, "
            f"{md.fields_only_in_b} solo en B."
        )
    else:
        lines.append("Metadata EXIF: sin diferencias en campos extraídos.")

    vd = result.visual
    if vd.applicable and vd.dimensions_match:
        if vd.pixels_identical:
            lines.append(
                "Píxeles IDÉNTICOS — la diferencia binaria está solo en "
                "metadata/headers, no en el contenido visual."
            )
        else:
            lines.append(
                f"Píxeles distintos: {vd.diff_pixels:,} de {vd.total_pixels:,} "
                f"({vd.diff_ratio*100:.2f}%), diferencia media {vd.mean_pixel_diff:.2f}/255."
            )
    elif vd.skip_reason:
        lines.append(f"Comparación visual: {vd.skip_reason}")

    result.summary = " ".join(lines)


def compare(
    image_a: str | Path,
    image_b: str | Path,
) -> DiffResult:
    """
    Compara dos imágenes provistas por el analista en tres niveles:
    binario, metadata, y visual.

    Args:
        image_a: ruta de la primera imagen.
        image_b: ruta de la segunda imagen.

    Returns:
        DiffResult con el detalle completo de las diferencias.
        Si los archivos son idénticos (mismo SHA-256), el resultado
        lo dice directamente sin análisis innecesario.
    """
    result = DiffResult(
        image_a=str(image_a),
        image_b=str(image_b),
    )

    path_a = Path(image_a)
    path_b = Path(image_b)

    if not path_a.exists():
        result.error = f"imagen A no encontrada: {image_a}"
        return result
    if not path_b.exists():
        result.error = f"imagen B no encontrada: {image_b}"
        return result

    # Nivel 1: binario
    result.binary = _compare_binary(path_a, path_b)

    if result.binary.identical:
        _build_summary(result)
        return result

    # Nivel 2: metadata (solo si son distintas)
    meta_a = extract(path_a)
    meta_b = extract(path_b)
    result.metadata = _compare_metadata(meta_a, meta_b)

    # Nivel 3: visual
    result.visual = _compare_visual(path_a, path_b)

    _build_summary(result)
    return result
