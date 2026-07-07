# vtr-forensic-img

> Herramienta de análisis forense de imágenes para auditoría de
> autenticidad, detección de manipulación, y recuperación de
> proveniencia. Desarrollada bajo los principios operativos de
> **Vector Telemetry Research** — cada byte declarado se verifica,
> ningún null se rellena silenciosamente.

## Estado actual — v0.1.0

Operativo. Probado contra imágenes JPEG reales con GPS, imágenes
simuladas de IA, y casos de timestamps inconsistentes. El parser
binario en Rust compila y corre en Linux (Ubuntu 24, Rust 1.75+).

```
Componente               Líneas    Estado
─────────────────────────────────────────
core/metadata_extractor  550       ✅ Operativo
core/ela_analyzer        285       ✅ Operativo
core/consistency_checker 402       ✅ Operativo
core/provenance_report   226       ✅ Operativo
core/rust_bridge         244       ✅ Operativo
cli.py                   103       ✅ Operativo
rust_parser/src/main.rs  541       ✅ Compilado
─────────────────────────────────────────
Total                    2352
```

## Qué hace

Analiza una imagen (local o URL) y produce un reporte forense que
integra dos corrientes simultáneamente:

**Corriente 1 — Autenticidad / detección de IA**
- Marcadores de software generador de IA en metadata (Stable Diffusion,
  Midjourney, DALL-E, y otros)
- Ausencia estructural de metadata de cámara (sin fabricante, modelo,
  ni parámetros de captura)
- Error Level Analysis (ELA) — distribución anómala de compresión JPEG
  que indica edición localizada post-captura
- Thumbnail embebido inconsistente con imagen principal (recorte posterior)

**Corriente 2 — Proveniencia / contexto genealógico y forense**
- Extracción completa de EXIF/XMP/IPTC/PNG chunks con fuente exacta
- GPS con validación de rangos físicamente posibles
- Línea de tiempo reconstruida: EXIF Original vs. Digitized vs. filesystem
- Identificación del dispositivo de captura (fabricante, modelo, serie)
- Historial de software de edición

**Capa de seguridad binaria (Rust)**
- Parser JPEG: markers con offsets exactos, detección de truncamiento,
  trailing bytes tras EOI, segmentos APP1/COM
- Parser PNG: CRC32 verificado por chunk, datos post-IEND, chunks anómalos
- SHA-256 + MD5 para cadena de custodia, verificación cruzada con Python

## Estructura del repositorio

```
vtr-forensic-img/
├── cli.py                      — interfaz de línea de comandos
├── core/
│   ├── __init__.py
│   ├── metadata_extractor.py   — EXIF/XMP/GPS/timestamps (Python)
│   ├── ela_analyzer.py         — Error Level Analysis
│   ├── consistency_checker.py  — hallazgos forenses + señales AI
│   ├── provenance_report.py    — ensamblador del reporte final
│   └── rust_bridge.py          — bridge Python↔Rust
├── rust_parser/
│   ├── Cargo.toml              — dependencias Rust (mínimas deliberadas)
│   └── src/
│       └── main.rs             — parser binario JPEG/PNG
├── README.md
└── ARCHITECTURE.md
```

## Instalación

### Dependencias Python

```bash
pip install exifread piexif numpy scipy requests pillow
```

### Parser Rust (recomendado, no obligatorio)

```bash
cd rust_parser
cargo build --release
export VTR_RUST_PARSER_BIN=$(pwd)/target/release/vtr_image_parser
```

Si el binario Rust no está disponible, el pipeline continúa con los
parsers Python — registrado explícitamente en el reporte, nunca en
silencio.

### Variable de entorno permanente

```bash
echo 'export VTR_RUST_PARSER_BIN=~/vtr-forensic-img/rust_parser/target/release/vtr_image_parser' >> ~/.bashrc
```

## Uso

```bash
# Imagen local
python3 cli.py analyze foto.jpg

# URL remota
python3 cli.py analyze https://ejemplo.com/imagen.jpg

# Salida JSON (para automatización)
python3 cli.py analyze foto.jpg --json

# Sin ELA (más rápido)
python3 cli.py analyze foto.jpg --no-ela

# Guardar reporte
python3 cli.py analyze foto.jpg --output reporte.txt

# Ajustar umbral de ELA (default 15.0, escala 0-255)
python3 cli.py analyze foto.jpg --ela-threshold 20
```

**Exit codes** (útiles en pipelines automatizados):
- `0` — análisis completado, nivel de riesgo BAJO
- `1` — nivel de riesgo BAJO-MEDIO o MEDIO
- `2` — nivel de riesgo ALTO

## Ejemplo de reporte real

```
VTR FORENSIC IMAGE ANALYZER v0.1.0
Archivo:    DSCN0010.jpg
Análisis:   2026-07-07T00:06:32Z

── DISPOSITIVO ─────────────────────────────────
  Fabricante: NIKON
  Modelo:     COOLPIX P6000
  Software:   Nikon Transfer 1.1 W

── GPS ──────────────────────────────────────────
  Latitud:  43.467448
  Longitud: 11.885127        ← Siena, Italia
  Válido:   SÍ

── ELA ──────────────────────────────────────────
  Error medio:    2.163
  Bloques anóm.:  0.0%
  Confianza:      BAJA sospecha de manipulación

── HALLAZGOS ────────────────────────────────────
  Nivel de riesgo: BAJO
  Sin hallazgos de inconsistencia.
```

## Decisiones de diseño relevantes para un auditor

**100% offline.** Ningún dato de imagen se envía a servicios externos.
En un contexto forense, enviar la imagen a un servicio de terceros
rompe la cadena de custodia — la imagen es la evidencia.

**`None` es distinto de `""`.**  Un campo ausente en la metadata y un
campo presente con valor vacío son estados forenses distintos. Ninguno
se colapsa en el otro silenciosamente.

**El parser Rust verifica CRC32 por chunk PNG.** Un CRC inválido
significa que los datos del chunk fueron modificados después de que el
archivo fue escrito — el reporte lo marca como anomalía de severidad
ALTA con el offset exacto en bytes.

**ELA es un indicador, no una prueba.** El reporte lo dice
explícitamente, incluyendo el umbral y la calidad de recompresión
usados, para que cualquier auditor pueda reproducir el análisis con
los mismos parámetros o cuestionarlos.

## Lo que este proyecto NO hace (v0.1.0)

- No analiza WEBP, GIF, TIFF, o RAW (parser Rust los detecta por
  firma pero no los parsea internamente)
- No tiene interfaz web (planificado para v0.2.0)
- No tiene tests formales de pytest (planificado para v0.2.0)
- No usa APIs externas de detección de IA — decisión deliberada,
  no limitación técnica

---

Vector Telemetry Research © 2026 — SIGNAL. VECTOR. INTELLIGENCE.
