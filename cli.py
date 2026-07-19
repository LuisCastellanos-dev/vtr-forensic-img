#!/usr/bin/env python3
"""
vtr-forensic-img v0.2.0
cli.py — Interfaz de línea de comandos

Uso:
    python3 cli.py analyze <imagen>
    python3 cli.py analyze <imagen> --strict
    python3 cli.py analyze <imagen> --json --output reporte.json
    python3 cli.py analyze <imagen> --verify-signature firma.sig --public-key device.pub
    python3 cli.py diff <imagen_a> <imagen_b>
    python3 cli.py diff <imagen_a> <imagen_b> --json
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.provenance_report import generate, to_json, to_text
from core.strict_mode import StrictModeViolation


def cmd_analyze(args: argparse.Namespace) -> int:
    print(f"[vtr-forensic] Analizando: {args.image}", file=sys.stderr)
    print(f"[vtr-forensic] ELA: {'deshabilitado' if args.no_ela else f'habilitado (umbral={args.ela_threshold})'}", file=sys.stderr)
    if args.strict:
        print("[vtr-forensic] MODO ESTRICTO — el análisis se detendrá al primer error estructural", file=sys.stderr)

    try:
        report = generate(
            image_source=args.image,
            ela_quality=args.ela_quality,
            ela_threshold=args.ela_threshold,
            include_ela_image=not args.no_ela,
            strict=args.strict,
        )
    except StrictModeViolation as exc:
        print(f"\n[STRICT MODE] Análisis detenido: {exc}", file=sys.stderr)
        print(f"  Campo:  {exc.field_name}", file=sys.stderr)
        print(f"  Razón:  {exc.reason}", file=sys.stderr)
        if exc.byte_offset is not None:
            print(f"  Offset: 0x{exc.byte_offset:X}", file=sys.stderr)
        return 3

    # Verificación de firma Ed25519 (opcional)
    if args.verify_signature and args.public_key:
        from core.signature_verifier import verify_signature

        try:
            sig_bytes = Path(args.verify_signature).read_bytes()
            pub_bytes = Path(args.public_key).read_bytes()
        except FileNotFoundError as e:
            print(f"[vtr-forensic] Error: {e}", file=sys.stderr)
            return 1

        result = verify_signature(args.image, sig_bytes, pub_bytes)
        report["signature_verification"] = {
            "verified": result.verified,
            "error": result.error,
            "detail": result.detail,
            "image_sha256": result.image_sha256,
            "public_key_hex": result.public_key_hex,
        }
        if not args.json:
            print()
            print("── VERIFICACIÓN DE FIRMA Ed25519 ─────────────────────────────────")
            if result.verified:
                print(f"  ✓ FIRMA VÁLIDA")
            else:
                print(f"  ✗ FIRMA INVÁLIDA: {result.error}")
            print(f"  {result.detail}")
            print()

    if args.json:
        output = to_json(report)
    else:
        output = to_text(report)

    if args.output:
        Path(args.output).write_text(output, encoding='utf-8')
        print(f"[vtr-forensic] Reporte guardado en: {args.output}", file=sys.stderr)
    else:
        print(output)

    risk = report.get("consistency", {}).get("risk_level", "INDETERMINADO")
    return 2 if risk == "ALTO" else 1 if "MEDIO" in risk else 0


def cmd_diff(args: argparse.Namespace) -> int:
    """Comparación diferencial entre dos imágenes."""
    from core.diff_analyzer import compare
    from dataclasses import asdict

    print(f"[vtr-forensic] Comparando:", file=sys.stderr)
    print(f"  A: {args.image_a}", file=sys.stderr)
    print(f"  B: {args.image_b}", file=sys.stderr)

    result = compare(args.image_a, args.image_b)

    if result.error:
        print(f"[vtr-forensic] Error: {result.error}", file=sys.stderr)
        return 1

    if args.json:
        # Serializar a JSON — convertir dataclasses anidadas
        def dc_to_dict(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return {k: dc_to_dict(v) for k, v in asdict(obj).items()}
            if isinstance(obj, list):
                return [dc_to_dict(i) for i in obj]
            return obj

        output = json.dumps(dc_to_dict(result), ensure_ascii=False, indent=2, default=str)
    else:
        lines = [
            "=" * 60,
            "VTR FORENSIC — COMPARACIÓN DIFERENCIAL",
            "=" * 60,
            f"  Imagen A: {result.image_a}",
            f"  Imagen B: {result.image_b}",
            "",
            "── BINARIO ───────────────────────────────────────────────────",
            f"  Idénticas:     {'SÍ' if result.binary.identical else 'NO'}",
            f"  SHA-256 A:     {result.binary.sha256_a}",
            f"  SHA-256 B:     {result.binary.sha256_b}",
            f"  Tamaño A:      {result.binary.size_a:,} bytes",
            f"  Tamaño B:      {result.binary.size_b:,} bytes",
            f"  Diferencia:    {result.binary.size_difference:+,} bytes",
        ]

        if not result.binary.identical:
            if result.binary.first_diff_offset is not None:
                lines.append(f"  Primer diff:   offset 0x{result.binary.first_diff_offset:X}")
            lines.append(f"  Bytes distintos: {result.binary.total_diff_bytes:,}")

            # Metadata diff
            md = result.metadata
            if md.fields_different or md.fields_only_in_a or md.fields_only_in_b:
                lines += [
                    "",
                    "── METADATA ──────────────────────────────────────────────────",
                    f"  Campos idénticos:    {md.fields_identical}",
                    f"  Campos cambiados:    {md.fields_different}",
                    f"  Solo en A:           {md.fields_only_in_a}",
                    f"  Solo en B:           {md.fields_only_in_b}",
                ]
                for d in md.differences[:15]:
                    val_a = d.value_a if d.value_a is not None else "(ausente)"
                    val_b = d.value_b if d.value_b is not None else "(ausente)"
                    lines.append(f"    [{d.diff_type}] {d.field_name}")
                    lines.append(f"      A: {str(val_a)[:80]}")
                    lines.append(f"      B: {str(val_b)[:80]}")

            # Visual diff
            vd = result.visual
            if vd.applicable and vd.dimensions_match:
                lines += [
                    "",
                    "── VISUAL ────────────────────────────────────────────────────",
                    f"  Dimensiones:   {'coinciden' if vd.dimensions_match else 'DISTINTAS'}",
                    f"  Píxeles iguales: {'SÍ' if vd.pixels_identical else 'NO'}",
                ]
                if not vd.pixels_identical:
                    lines += [
                        f"  Píxeles distintos: {vd.diff_pixels:,} de {vd.total_pixels:,} ({vd.diff_ratio*100:.2f}%)",
                        f"  Diff media:    {vd.mean_pixel_diff:.2f} / 255",
                        f"  Diff máxima:   {vd.max_pixel_diff:.0f} / 255",
                    ]
            elif vd.skip_reason:
                lines += ["", f"  Visual: {vd.skip_reason}"]

        lines += [
            "",
            "── RESUMEN ───────────────────────────────────────────────────",
            f"  {result.summary}",
            "",
            "=" * 60,
        ]
        output = "\n".join(lines)

    if args.output:
        Path(args.output).write_text(output, encoding='utf-8')
        print(f"[vtr-forensic] Reporte guardado en: {args.output}", file=sys.stderr)
    else:
        print(output)

    return 0 if result.binary.identical else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VTR Forensic Image Analyzer — análisis forense de metadata e integridad"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── analyze ───────────────────────────────────────────────
    p_analyze = subparsers.add_parser(
        "analyze",
        help="Analizar una imagen (ruta local o URL)"
    )
    p_analyze.add_argument(
        "image",
        help="Ruta de archivo local o URL HTTP/HTTPS de la imagen"
    )
    p_analyze.add_argument(
        "--json", action="store_true",
        help="Salida en formato JSON (por defecto: texto plano)"
    )
    p_analyze.add_argument(
        "--output", "-o",
        help="Guardar reporte a archivo (por defecto: stdout)"
    )
    p_analyze.add_argument(
        "--strict", action="store_true",
        help="Modo estricto: detener al primer error estructural"
    )
    p_analyze.add_argument(
        "--no-ela", action="store_true",
        help="Deshabilitar ELA (más rápido)"
    )
    p_analyze.add_argument(
        "--ela-quality", type=int, default=95,
        help="Calidad JPEG para recompresión ELA (default: 95)"
    )
    p_analyze.add_argument(
        "--ela-threshold", type=float, default=15.0,
        help="Umbral de anomalía ELA, escala 0-255 (default: 15.0)"
    )
    p_analyze.add_argument(
        "--verify-signature",
        help="Ruta al archivo de firma Ed25519 (64 bytes)"
    )
    p_analyze.add_argument(
        "--public-key",
        help="Ruta al archivo de llave pública Ed25519 (32 bytes)"
    )
    p_analyze.set_defaults(func=cmd_analyze)

    # ── diff ──────────────────────────────────────────────────
    p_diff = subparsers.add_parser(
        "diff",
        help="Comparar dos imágenes (binario, metadata, visual)"
    )
    p_diff.add_argument(
        "image_a",
        help="Ruta de la primera imagen"
    )
    p_diff.add_argument(
        "image_b",
        help="Ruta de la segunda imagen"
    )
    p_diff.add_argument(
        "--json", action="store_true",
        help="Salida en formato JSON"
    )
    p_diff.add_argument(
        "--output", "-o",
        help="Guardar reporte a archivo"
    )
    p_diff.set_defaults(func=cmd_diff)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
