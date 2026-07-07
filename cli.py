#!/usr/bin/env python3
"""
vtr-forensic-img v0.1.0
cli.py — Interfaz de línea de comandos

Uso:
    python3 cli.py analyze <imagen_o_url>
    python3 cli.py analyze <imagen> --json
    python3 cli.py analyze <imagen> --output reporte.txt
    python3 cli.py analyze <imagen> --ela-threshold 20
    python3 cli.py analyze <imagen> --no-ela
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.provenance_report import generate, to_json, to_text


def cmd_analyze(args: argparse.Namespace) -> int:
    print(f"[vtr-forensic] Analizando: {args.image}", file=sys.stderr)
    print(f"[vtr-forensic] ELA: {'deshabilitado' if args.no_ela else f'habilitado (umbral={args.ela_threshold})'}", file=sys.stderr)

    report = generate(
        image_source=args.image,
        ela_quality=args.ela_quality,
        ela_threshold=args.ela_threshold,
        include_ela_image=not args.no_ela,
    )

    if args.json:
        output = to_json(report)
    else:
        output = to_text(report)

    if args.output:
        Path(args.output).write_text(output, encoding='utf-8')
        print(f"[vtr-forensic] Reporte guardado en: {args.output}", file=sys.stderr)
    else:
        print(output)

    # Exit code refleja el nivel de riesgo — útil para pipelines automatizados
    risk = report.get("consistency", {}).get("risk_level", "INDETERMINADO")
    return 2 if risk == "ALTO" else 1 if "MEDIO" in risk else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VTR Forensic Image Analyzer — análisis forense de metadata e integridad"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_analyze = subparsers.add_parser(
        "analyze",
        help="Analizar una imagen (ruta local o URL)"
    )
    p_analyze.add_argument(
        "image",
        help="Ruta de archivo local o URL HTTP/HTTPS de la imagen"
    )
    p_analyze.add_argument(
        "--json",
        action="store_true",
        help="Salida en formato JSON (por defecto: texto plano)"
    )
    p_analyze.add_argument(
        "--output", "-o",
        help="Guardar reporte a archivo (por defecto: stdout)"
    )
    p_analyze.add_argument(
        "--no-ela",
        action="store_true",
        help="Deshabilitar ELA (más rápido, menos análisis)"
    )
    p_analyze.add_argument(
        "--ela-quality",
        type=int,
        default=95,
        help="Calidad JPEG para recompresión ELA (default: 95)"
    )
    p_analyze.add_argument(
        "--ela-threshold",
        type=float,
        default=15.0,
        help="Umbral de anomalía ELA, escala 0-255 (default: 15.0)"
    )
    p_analyze.set_defaults(func=cmd_analyze)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
