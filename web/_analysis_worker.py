"""
vtr-forensic-img v0.1.0
web/_analysis_worker.py

Worker de análisis aislado — corre como subproceso independiente.

PROPÓSITO DEL AISLAMIENTO:
  Este script es invocado por web/app.py via subprocess.run().
  El servidor principal nunca importa el pipeline de análisis
  directamente — toda interacción con bytes de imagen ocurre
  en este proceso separado. Si una imagen maliciosa corrompe
  el estado de este proceso (crash, heap corruption, loop infinito),
  el servidor principal no se ve afectado.

  Output: una línea de JSON a stdout.
  Errores: a stderr (el servidor los loguea, no los expone al cliente).

MITIGACIÓN FUTURA preparada en este diseño:
  El aislamiento por subproceso es el primer nivel. Los siguientes
  niveles (no implementados en v0.1.0) son:
  - seccomp: limitar las syscalls que este proceso puede hacer
  - namespaces: aislar filesystem y red
  - rlimits: limitar memoria y tiempo de CPU
  Todos aplican a este proceso sin cambiar el servidor principal.
"""

import json
import sys
import os
from pathlib import Path

# Insertar el directorio del proyecto en sys.path
PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("image_path", help="Ruta del archivo de imagen temporal")
    parser.add_argument("--url", default=None, help="URL de imagen remota")
    args = parser.parse_args()

    try:
        from core.provenance_report import generate, to_json

        if args.url:
            source = args.url
        else:
            source = args.image_path

        report = generate(image_source=source)
        print(json.dumps(report, ensure_ascii=False, default=str))
        sys.exit(0)

    except Exception as e:
        error = {"error": str(e)[:500], "worker": "_analysis_worker.py"}
        print(json.dumps(error))
        sys.exit(1)


if __name__ == "__main__":
    main()
