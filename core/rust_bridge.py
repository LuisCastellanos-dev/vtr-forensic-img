"""
vtr-forensic-img v0.1.0
core/rust_bridge.py

Bridge entre Python y el parser binario en Rust.

ARQUITECTURA:
  Python llama al binario Rust como subproceso — stdout JSON, stderr
  mensajes de diagnóstico. Esta interfaz de texto bien tipado es
  deliberada: no FFI, no ctypes, no complejidad de lifetimes cruzando
  la frontera. El boundary es auditablemente simple.

FALLBACK:
  Si el binario Rust no está disponible (entorno sin compilación,
  tests en CI sin cargo), el bridge retorna None y el pipeline Python
  continúa usando sus propios parsers. Esto se registra explícitamente
  — nunca silenciosamente. La premisa VTR aplica al bridge mismo:
  "ausente y registrado" es distinto de "ausente silenciosamente".

COMPATIBILIDAD DE SO (Linux / macOS / Windows):
  El binario Rust compilado tiene nombre distinto según el SO:
  - Linux / macOS: vtr_image_parser
  - Windows:       vtr_image_parser.exe
  La función _binary_name() resuelve esto en tiempo de ejecución.

  os.access(path, os.X_OK) no tiene significado en Windows (siempre
  retorna True para archivos existentes). En Windows, la verificación
  de ejecutabilidad se hace por extensión (.exe) y existencia del
  archivo — is_file() es suficiente en ese SO.

  Compilación en cada SO:
    Linux/macOS:  cargo build --release
    Windows:      cargo build --release  (mismos comandos, diferente output)
"""

from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_MODULE_DIR = Path(__file__).resolve().parent
_IS_WINDOWS = platform.system() == "Windows"


def _binary_name() -> str:
    """
    Nombre del binario Rust según el SO — con extensión correcta.
    En Windows, cargo produce vtr_image_parser.exe, no vtr_image_parser.
    """
    return "vtr_image_parser.exe" if _IS_WINDOWS else "vtr_image_parser"


def _is_executable(path: Path) -> bool:
    """
    Verifica si un archivo es ejecutable de forma portable.
    - Linux/macOS: os.access(path, os.X_OK) es la verificación real.
    - Windows: os.X_OK siempre retorna True para archivos existentes,
      así que verificamos solo que exista y sea .exe.
    """
    if not path.is_file():
        return False
    if _IS_WINDOWS:
        return path.suffix.lower() == ".exe"
    return os.access(path, os.X_OK)


def _find_binary() -> Path | None:
    """
    Localiza el binario Rust. Orden de búsqueda explícito, no implícito:
    1. Variable de entorno VTR_RUST_PARSER_BIN (deployment, prioridad máxima)
    2. Ruta relativa al módulo (desarrollo local, cargo build --release)
    3. PATH del sistema (instalación global)
    No asume que existe — retorna None si no lo encuentra.
    """
    name = _binary_name()

    # 1. Variable de entorno explícita
    env_path = os.environ.get("VTR_RUST_PARSER_BIN")
    if env_path:
        p = Path(env_path)
        # En Windows, el usuario puede omitir la extensión .exe — la agregamos
        if _IS_WINDOWS and not p.suffix:
            p = p.with_suffix(".exe")
        if _is_executable(p):
            return p
        logger.warning(
            "[rust_bridge] VTR_RUST_PARSER_BIN=%s no es ejecutable o no existe",
            env_path
        )

    # 2. Rutas relativas al módulo (build local)
    candidates = [
        _MODULE_DIR.parent / "rust_parser" / "target" / "release" / name,
        _MODULE_DIR.parent / "rust_parser" / name,
        _MODULE_DIR.parent.parent / "vtr_forensic_rust" / "target" / "release" / name,
    ]
    for candidate in candidates:
        if _is_executable(candidate):
            return candidate

    # 3. PATH del sistema
    import shutil
    which = shutil.which(name)
    # shutil.which ya maneja PATHEXT en Windows correctamente
    if which:
        return Path(which)

    return None


def parse_binary(image_path: str | Path) -> dict[str, Any] | None:
    """
    Invoca el parser Rust sobre una imagen y retorna el JSON parseado.

    Returns:
        dict con el resultado del parser Rust, o None si el binario no
        está disponible o falla. El caller debe tratar None como
        "parser Rust no disponible" y continuar con el pipeline Python —
        nunca como "la imagen no tiene anomalías".

    Raises:
        Nunca — todos los errores se capturan y se loguean. El pipeline
        principal no debe romperse por ausencia del componente Rust.
    """
    binary = _find_binary()
    if binary is None:
        logger.info(
            "[rust_bridge] binario Rust no encontrado — "
            "continuando con parsers Python solamente. "
            "Para habilitar el parser Rust: cargo build --release "
            "en vtr_forensic_rust/ y configurar VTR_RUST_PARSER_BIN"
        )
        return None

    try:
        result = subprocess.run(
            [str(binary), str(image_path)],
            capture_output=True,
            text=True,
            timeout=30,  # 30s máximo — imágenes maliciosas no deben colgar el proceso
        )

        # stderr siempre es diagnóstico del parser — loguearlo, no suprimirlo
        if result.stderr.strip():
            logger.debug("[rust_bridge] stderr: %s", result.stderr.strip())

        if result.returncode == 1:
            logger.warning(
                "[rust_bridge] parser Rust error de IO para '%s': %s",
                image_path, result.stderr.strip()
            )
            return None

        if result.returncode == 2:
            # Formato no reconocido — es información, no error
            logger.info("[rust_bridge] formato no reconocido: '%s'", image_path)
            # El JSON parcial todavía puede tener anomalías útiles
            # intentamos parsearlo de todas formas

        if not result.stdout.strip():
            logger.warning("[rust_bridge] salida vacía para '%s'", image_path)
            return None

        parsed = json.loads(result.stdout.strip())
        return parsed

    except subprocess.TimeoutExpired:
        logger.error(
            "[rust_bridge] timeout (30s) procesando '%s' — "
            "imagen posiblemente maliciosa o muy grande",
            image_path
        )
        return None
    except json.JSONDecodeError as e:
        logger.error(
            "[rust_bridge] JSON inválido del parser para '%s': %s",
            image_path, str(e)[:100]
        )
        return None
    except Exception as e:
        logger.error("[rust_bridge] error inesperado: %s", str(e)[:200])
        return None


def merge_rust_findings(
    python_meta: "ImageMetadata",  # type: ignore
    rust_result: dict[str, Any] | None,
) -> None:
    """
    Integra los hallazgos del parser Rust en el ImageMetadata de Python.
    Solo agrega información — nunca sobreescribe lo que Python ya encontró.
    Cada hallazgo agregado se marca con fuente 'rust_parser' para
    trazabilidad en el reporte.

    Principio: si Rust encuentra una anomalía que Python no encontró,
    eso es información adicional genuina. Si Python encontró algo que
    Rust no encontró (por ejemplo, campos EXIF de alto nivel que Rust
    no parsea), Python tiene razón — no se descarta.
    """
    if rust_result is None:
        return

    # Verificar consistencia de hashes
    rust_sha256 = rust_result.get("hashes", {}).get("sha256")
    if rust_sha256 and python_meta.sha256 and rust_sha256 != python_meta.sha256:
        python_meta.security.structurally_anomalous.append(
            f"[rust_parser] DISCREPANCIA DE HASH: "
            f"Rust calculó SHA256={rust_sha256}, "
            f"Python calculó {python_meta.sha256} — "
            f"esto no debería ocurrir nunca; indica un bug en el bridge "
            f"o que el archivo fue modificado entre las dos lecturas"
        )

    # Agregar anomalías de estructura binaria detectadas por Rust
    for anomaly in rust_result.get("anomalies", []):
        severity = anomaly.get("severity", "?")
        category = anomaly.get("category", "?")
        description = anomaly.get("description", "")
        offset = anomaly.get("byte_offset")

        offset_str = f" (offset 0x{offset:X})" if offset is not None else ""
        message = f"[rust_parser/{category}/{severity}]{offset_str} {description}"

        if severity == "HIGH":
            python_meta.security.structurally_anomalous.append(message)
        else:
            python_meta.extraction_warnings.append(message)

    # Warnings del parser Rust
    for warning in rust_result.get("parse_warnings", []):
        python_meta.extraction_warnings.append(f"[rust_parser] {warning}")

    # Información de chunks PNG de texto (puede complementar lo que Python extrajo)
    rust_png = rust_result.get("png")
    if rust_png:
        for chunk in rust_png.get("chunks", []):
            tc = chunk.get("text_content")
            if tc and tc.get("key"):
                key = tc["key"]
                val = tc.get("value")  # None es distinto de ""
                crc_ok = chunk.get("crc_valid")

                # Solo agregar si Python no lo encontró ya
                if key not in python_meta.png_text_chunks:
                    if val is not None:
                        python_meta.png_text_chunks[key] = val
                    # Si val es None: el chunk existía con clave pero sin valor
                    # Eso es información forense — lo registramos diferente a
                    # "clave con valor vacío"
                    elif val is None:
                        python_meta.extraction_warnings.append(
                            f"[rust_parser] PNG chunk '{key}': clave presente, valor ausente"
                        )

                # CRC inválido en un chunk de texto es alta relevancia forense
                if crc_ok is False:
                    python_meta.security.structurally_anomalous.append(
                        f"[rust_parser] CRC inválido en chunk PNG '{key}' "
                        f"offset={chunk.get('offset', '?')} — "
                        f"datos del chunk modificados post-escritura"
                    )

    # JPEG: trailing bytes y structure anomalies ya se agregan vía anomalies[]
    # Los markers JPEG se registran en extraction_warnings si hay truncamiento
    rust_jpeg = rust_result.get("jpeg")
    if rust_jpeg:
        if rust_jpeg.get("trailing_bytes", 0) > 0:
            # Ya está en anomalies[], no duplicar
            pass

        for marker in rust_jpeg.get("markers_found", []):
            if marker.get("truncated"):
                python_meta.extraction_warnings.append(
                    f"[rust_parser] Marker JPEG '{marker.get('marker')}' "
                    f"truncado en offset {marker.get('offset', '?')}: "
                    f"declarado {marker.get('declared_length')} bytes, "
                    f"disponible {marker.get('actual_bytes_available')} bytes"
                )
