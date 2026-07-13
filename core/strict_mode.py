"""
vtr-forensic-img v0.2.0
core/strict_mode.py

Modo Estricto vs. Modo Forense — control centralizado.

DOS MODOS, UN SOLO PIPELINE:
  El código de parsing es el mismo en ambos modos. La diferencia es
  qué pasa cuando un campo no cumple la especificación:

  Modo Forense (default):
    El error se registra (parse_errors, extraction_warnings) y el
    análisis continúa — el analista recibe un reporte parcial pero
    con todas las anomalías documentadas. Útil cuando la pregunta es
    "¿qué puedo extraer de este archivo, incluyendo evidencia de
    corrupción?"

  Modo Estricto (--strict):
    El error detiene el análisis inmediatamente con una excepción
    StrictModeViolation que incluye el offset, campo, y motivo exacto.
    Útil cuando la pregunta es "¿este archivo cumple la especificación
    sin ninguna desviación?" — cualquier continuación pasaría
    información a través de datos potencialmente corruptos.

IMPLEMENTACIÓN:
  No hay 20 if/else en cada except. Hay un AnalysisContext que se
  pasa a las funciones de parsing y que decide, en un solo lugar,
  si registrar o lanzar. Las funciones llaman ctx.record_error() —
  el contexto decide qué hacer según el modo.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class StrictModeViolation(Exception):
    """
    Se lanza en modo estricto cuando el parser encuentra cualquier
    desviación de la especificación del formato.

    Atributos accesibles:
      - field_name: qué campo o estructura falló
      - byte_offset: dónde en el archivo (None si no aplica)
      - reason: descripción legible del problema
    """

    def __init__(
        self,
        field_name: str,
        reason: str,
        byte_offset: int | None = None,
    ):
        self.field_name = field_name
        self.reason = reason
        self.byte_offset = byte_offset
        offset_str = f" (offset 0x{byte_offset:X})" if byte_offset is not None else ""
        super().__init__(f"[STRICT]{offset_str} {field_name}: {reason}")


@dataclass
class AnalysisContext:
    """
    Contexto compartido por todas las funciones de parsing durante
    un análisis. Centraliza la decisión de modo estricto vs. forense.

    Uso en las funciones de parsing:
        ctx.record_error("GPS GPSAltitude", "denominador cero")
        ctx.record_warning("timestamps de filesystem", "no se pudo leer")

    En modo forense: registra y continúa.
    En modo estricto: lanza StrictModeViolation inmediatamente.
    """

    strict: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    oversized_fields: list[str] = field(default_factory=list)
    non_printable_fields: list[str] = field(default_factory=list)
    structural_anomalies: list[str] = field(default_factory=list)

    def record_error(
        self,
        field_name: str,
        reason: str,
        byte_offset: int | None = None,
    ) -> None:
        """
        Registra un error de parsing. En modo estricto, lanza
        inmediatamente — en modo forense, acumula para el reporte.
        """
        message = f"{field_name}: {reason}"
        if byte_offset is not None:
            message = f"{field_name} (offset 0x{byte_offset:X}): {reason}"

        if self.strict:
            raise StrictModeViolation(field_name, reason, byte_offset)

        self.errors.append(message)

    def record_warning(
        self,
        field_name: str,
        reason: str,
    ) -> None:
        """
        Registra una advertencia. En modo estricto, las advertencias
        también detienen el análisis — si el analista eligió modo
        estricto, es porque cualquier desviación es inaceptable.
        """
        message = f"{field_name}: {reason}"

        if self.strict:
            raise StrictModeViolation(field_name, reason)

        self.warnings.append(message)

    def record_oversized(self, field_name: str, length: int, max_length: int) -> None:
        message = f"{field_name}: {length} chars (truncado a {max_length})"

        if self.strict:
            raise StrictModeViolation(
                field_name,
                f"campo de {length} chars excede el límite de {max_length} — "
                f"en modo estricto, no se trunca ni se continúa"
            )

        self.oversized_fields.append(message)

    def record_non_printable(self, field_name: str, count: int) -> None:
        message = f"{field_name}: {count} caracteres anómalos detectados"

        if self.strict:
            raise StrictModeViolation(
                field_name,
                f"{count} caracteres no imprimibles encontrados — "
                f"en modo estricto, se rechaza el campo completo"
            )

        self.non_printable_fields.append(message)

    def record_structural(self, description: str, byte_offset: int | None = None) -> None:
        if byte_offset is not None:
            description = f"(offset 0x{byte_offset:X}) {description}"

        if self.strict:
            raise StrictModeViolation("STRUCTURE", description, byte_offset)

        self.structural_anomalies.append(description)
