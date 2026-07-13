"""
vtr-forensic-img v0.2.0
core/signature_verifier.py

Verificación de firma Ed25519 para cadena de custodia criptográfica.

PROPÓSITO:
  Verificar que una imagen fue firmada por el dispositivo que afirma
  haberla capturado — convierte "confiamos en que nadie la modificó"
  en "matemáticamente demostrable que no fue modificada desde que fue
  firmada con la llave privada correspondiente a esta llave pública."

DECISIÓN ARQUITECTÓNICA (documentada, no asumida):
  Este módulo implementa la VERIFICACIÓN de firmas Ed25519 usando
  PyNaCl directamente — sin importar ningún código de vtr-continuity.
  La razón: vtr-continuity gestiona llaves (PKI de dos niveles,
  device_registry.vtrdb, CA Root/Intermediate); vtr-forensic-img
  solo verifica firmas contra llaves públicas provistas por el
  analista. Son responsabilidades distintas que no deben acoplarse.

  No se reimplementa ed25519_sign.py de Continuity. Se usa PyNaCl
  directamente (la misma biblioteca que Continuity usa internamente,
  con la misma restricción de versión >= 1.6.2 ya evaluada contra
  CVE-2025-69277). El resultado es funcionalmente equivalente pero
  sin dependencia de código ajeno.

FLUJO DE VERIFICACIÓN:
  1. El analista provee: imagen, firma (bytes), llave pública (bytes)
  2. Este módulo calcula SHA-256 de la imagen (misma cadena de custodia
     que ya aparece en el reporte)
  3. Verifica que la firma sobre ese hash corresponde a la llave pública
  4. Retorna un resultado tipado con el detalle de la verificación

QUÉ SE FIRMA (convención):
  La firma es sobre el SHA-256 del archivo completo (no sobre los
  píxeles ni sobre la metadata — sobre los bytes crudos). Esto
  significa que cualquier modificación al archivo, incluyendo
  re-compresión JPEG o cambio de metadata EXIF, invalida la firma.
  Eso es una propiedad, no un bug: la firma certifica la integridad
  bit a bit del archivo exacto que fue firmado.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path

import nacl.signing
import nacl.exceptions

logger = logging.getLogger(__name__)

# Tamaños fijos de Ed25519 — constantes, no configurables
PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64


@dataclass
class SignatureVerifyResult:
    """Resultado de una verificación de firma."""
    verified: bool = False
    error: str | None = None

    image_sha256: str = ""
    public_key_hex: str = ""
    signature_hex: str = ""

    detail: str = ""


def _compute_sha256(file_path: Path) -> str:
    """SHA-256 del archivo — mismo cálculo que metadata_extractor.py."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_signature(
    image_path: str | Path,
    signature: bytes,
    public_key: bytes,
) -> SignatureVerifyResult:
    """
    Verifica que la firma Ed25519 sobre el SHA-256 de la imagen
    corresponde a la llave pública provista.

    Args:
        image_path: ruta del archivo de imagen a verificar.
        signature: 64 bytes de firma Ed25519.
        public_key: 32 bytes de llave pública Ed25519.

    Returns:
        SignatureVerifyResult con el detalle completo de la verificación.
        verified=True solo si la firma es matemáticamente válida.
        verified=False con error descriptivo en cualquier otro caso —
        nunca lanza excepciones al caller.
    """
    result = SignatureVerifyResult()

    # Validar inputs — sin asumir, sin rellenar
    if not isinstance(public_key, bytes):
        result.error = f"public_key debe ser bytes, recibido {type(public_key).__name__}"
        result.detail = "La llave pública no tiene el tipo correcto."
        return result

    if len(public_key) != PUBLIC_KEY_SIZE:
        result.error = (
            f"public_key debe ser exactamente {PUBLIC_KEY_SIZE} bytes, "
            f"recibido {len(public_key)} — ¿es un archivo de llave binaria "
            f"cruda, no PEM/base64?"
        )
        result.detail = "Longitud de llave pública incorrecta."
        return result

    if not isinstance(signature, bytes):
        result.error = f"signature debe ser bytes, recibido {type(signature).__name__}"
        result.detail = "La firma no tiene el tipo correcto."
        return result

    if len(signature) != SIGNATURE_SIZE:
        result.error = (
            f"signature debe ser exactamente {SIGNATURE_SIZE} bytes, "
            f"recibido {len(signature)}"
        )
        result.detail = "Longitud de firma incorrecta."
        return result

    path = Path(image_path)
    if not path.exists():
        result.error = f"archivo no encontrado: {image_path}"
        result.detail = "El archivo de imagen no existe en la ruta indicada."
        return result

    if not path.is_file():
        result.error = f"la ruta no es un archivo: {image_path}"
        return result

    # Calcular SHA-256 de la imagen
    try:
        image_sha256 = _compute_sha256(path)
        result.image_sha256 = image_sha256
    except Exception as e:
        result.error = f"error al calcular SHA-256: {str(e)[:100]}"
        return result

    result.public_key_hex = public_key.hex()
    result.signature_hex = signature.hex()

    # Verificar la firma con PyNaCl
    try:
        verify_key = nacl.signing.VerifyKey(public_key)
        # La firma es sobre el SHA-256 como bytes (hex string encoded)
        message = image_sha256.encode("ascii")
        verify_key.verify(message, signature)

        result.verified = True
        result.detail = (
            f"Firma válida. La imagen '{path.name}' (SHA-256: {image_sha256[:16]}...) "
            f"fue firmada con la llave privada correspondiente a la llave pública "
            f"{public_key.hex()[:16]}... — el archivo no fue modificado desde la firma."
        )
        logger.info(
            "[signature_verifier] firma válida para %s (SHA-256: %s)",
            path.name, image_sha256[:16]
        )

    except nacl.exceptions.BadSignatureError:
        result.verified = False
        result.error = "firma inválida"
        result.detail = (
            f"La firma NO verifica contra la llave pública provista. "
            f"Posibles causas: (1) el archivo fue modificado después de ser firmado, "
            f"(2) la firma fue generada con una llave privada distinta a la "
            f"correspondiente a esta llave pública, o (3) la firma o la llave "
            f"están corruptas."
        )
        logger.warning(
            "[signature_verifier] firma INVÁLIDA para %s", path.name
        )

    except Exception as e:
        result.verified = False
        result.error = f"error durante verificación: {str(e)[:200]}"
        result.detail = "Error inesperado al verificar la firma."
        logger.error("[signature_verifier] error: %s", str(e))

    return result


def sign_image(
    image_path: str | Path,
    private_key: bytes,
) -> tuple[bytes, str]:
    """
    Firma el SHA-256 de una imagen con una llave privada Ed25519.

    NOTA: esta función existe para testing y para el flujo de captura
    en el dispositivo. En producción forense, la firma se genera en
    el dispositivo que captura la imagen — nunca en la máquina del
    analista (eso significaría que el analista tiene la llave privada
    del dispositivo, lo cual rompería el modelo de confianza).

    Args:
        image_path: ruta del archivo de imagen.
        private_key: 32 bytes de llave privada Ed25519 (seed).

    Returns:
        Tupla (signature_bytes, sha256_hex).

    Raises:
        ValueError: si la llave privada es inválida.
        FileNotFoundError: si la imagen no existe.
    """
    if not isinstance(private_key, bytes) or len(private_key) != PUBLIC_KEY_SIZE:
        raise ValueError(
            f"private_key debe ser exactamente {PUBLIC_KEY_SIZE} bytes, "
            f"recibido {len(private_key) if isinstance(private_key, bytes) else type(private_key).__name__}"
        )

    path = Path(image_path)
    if not path.exists():
        raise FileNotFoundError(f"archivo no encontrado: {image_path}")

    sha256 = _compute_sha256(path)
    signing_key = nacl.signing.SigningKey(private_key)
    signed = signing_key.sign(sha256.encode("ascii"))

    return signed.signature, sha256
