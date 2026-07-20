# vtr-forensic-img

> Herramienta de análisis forense de imágenes para auditoría de
> autenticidad, detección de manipulación, y recuperación de
> proveniencia. Desarrollada bajo los principios operativos de
> **Vector Telemetry Research** — cada byte declarado se verifica,
> ningún null se rellena silenciosamente.

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
├── cli.py                      — interfaz de línea de comandos (--strict, --no-ela, --json)
├── core/
│   ├── __init__.py
│   ├── metadata_extractor.py   — EXIF/XMP/GPS/timestamps (Python)
│   ├── ela_analyzer.py         — Error Level Analysis
│   ├── entropy_analyzer.py     — entropía de Shannon por bloques
│   ├── consistency_checker.py  — hallazgos forenses + señales AI
│   ├── signature_verifier.py   — verificación Ed25519 (PyNaCl, sin vtr-continuity)
│   ├── diff_analyzer.py        — comparación diferencial binario/metadata/visual
│   ├── strict_mode.py          — AnalysisContext estricto vs forense
│   ├── provenance_report.py    — ensamblador del reporte final
│   └── rust_bridge.py          — bridge Python↔Rust (portable Linux/macOS/Windows)
├── rust_parser/
│   ├── Cargo.toml              — dependencias Rust (mínimas deliberadas)
│   └── src/
│       └── main.rs             — parser binario JPEG/PNG
├── web/
│   ├── app.py                  — FastAPI + CSP estricto + localhost only
│   └── _analysis_worker.py     — proceso aislado por análisis
├── tests/
│   ├── conftest.py             — fixtures adversariales construidas byte a byte
│   ├── test_metadata_extractor.py
│   ├── test_metadata_extended.py — PNG chunks, thumbnail, GPS full, _safe_str
│   ├── test_consistency_checker.py
│   ├── test_ela_analyzer.py
│   ├── test_v020_modules.py    — strict, entropía, Ed25519, diff
│   ├── test_pipeline_integration.py — provenance_report, generate/to_text/to_json
│   ├── test_rust_bridge.py     — parse_binary, merge_rust_findings, fallbacks
│   └── test_adversarial.py     — pentester/auditor/forense cross-module
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

## Estado actual (v0.2.0 — operativo)

| Componente | Estado | Tests |
|---|---|---|
| Parser binario Rust (JPEG/PNG) | ✅ Operativo | 30 (rust_bridge) |
| Extracción de metadata EXIF/XMP/GPS | ✅ Operativo | 41 (extractor + extended) |
| Error Level Analysis (ELA) | ✅ Operativo | 14 |
| Detección de señales de IA generativa | ✅ Operativo | 14 |
| Consistency checker forense | ✅ Operativo | 13 |
| Interfaz web FastAPI (localhost, CSP) | ✅ Operativo | — |
| Modo estricto `--strict` | ✅ v0.2.0 | 10 |
| Entropía Shannon por bloques | ✅ v0.2.0 | 10 |
| Verificación firma Ed25519 | ✅ v0.2.0 | 10 |
| Comparación diferencial A/B | ✅ v0.2.0 | 12 |
| Pipeline integration | ✅ v0.2.0 | 28 (provenance_report 87%) |
| Suite adversarial (pentester/auditor/forense) | ✅ v0.2.0 | 36 |
| Portabilidad Linux/macOS/Windows | ✅ Aplicado | — |
| Parser WEBP/GIF/TIFF/RAW en Rust | 🔲 Detecta formato, no parsea | — |
| **Total tests** | **Coverage: 84%** | **210** |

## Lo que se construyó en v0.2.0 — y por qué

Cuatro módulos implementados. Cada uno fue evaluado contra la premisa
de integridad forense antes de aprobarse — solo se incorporó lo que
agrega valor trazable, sin inferencias ni dependencias cruzadas.

**1. Modo Estricto vs. Modo Forense (`--strict`)**

`core/strict_mode.py` — `AnalysisContext` centralizado que decide
en un solo lugar si registrar un error o lanzar `StrictModeViolation`.
Exit code 3 para violaciones de modo estricto. Sin 20 `if/else`
dispersos — las funciones de parsing llaman `ctx.record_error()` sin
saber en qué modo están.

```bash
python3 cli.py analyze imagen.jpg --strict
```

**2. Entropía de Shannon por bloques (`core/entropy_analyzer.py`)**

Complementa ELA: detecta aleatoriedad de bits (datos cifrados o
steganográficos insertados) vs. regiones clonadas (entropía anómala
baja). Incluye caveats explícitos y parámetros registrados en el output.

**3. Verificación de firma Ed25519 (`core/signature_verifier.py`)**

Verificación criptográfica de cadena de custodia — PyNaCl directo,
sin importar código de vtr-continuity. Un byte modificado invalida
la firma. Incluye `sign_image()` para testing y `verify_signature()`
para auditoría.

**4. Comparación diferencial (`core/diff_analyzer.py`)**

Tres niveles: binario (offset de primera diferencia, bytes distintos),
metadata (campos EXIF cambiados/añadidos/removidos), visual (píxeles
distintos con ratio). Nunca asume "imagen dorada" — el analista provee
ambas imágenes explícitamente.

**Portabilidad cross-OS (commit f1a618b)**

`rust_bridge.py` detecta nombre de binario por SO (`.exe` en Windows),
`_is_executable()` sin `os.X_OK` en Windows, `tempfile.mkstemp()` en
vez de `NamedTemporaryFile`, `shell=False` documentado explícitamente.

## Decisiones descartadas — con razón documentada

- **Importar `ed25519_sign.py` de vtr-continuity:** viola la regla
  de no mezcla entre repos VTR.
- **Comparación contra "imagen dorada" sin proveerla:** asumir una
  verdad de fábrica sin que el analista la provea es una afirmación
  no verificable.
- **YARA pattern matching:** reglas de terceros no verificables
  directamente. Opacidad incompatible con la premisa del proyecto.
- **APIs externas de detección de IA:** decisión permanente. Rompe
  la cadena de custodia forense.

## Lo que este proyecto NO hace (v0.2.0)

- No analiza WEBP, GIF, TIFF, o RAW internamente (el parser Rust
  detecta el formato por firma pero no recorre su estructura)
- No usa APIs externas de detección de IA — decisión deliberada,
  documentada en ARCHITECTURE.md
- No interpreta el contenido visual de la imagen (no reconoce
  personas, no lee texto embebido, no detecta anacronismos)

---

## Roadmap v0.3.0 — detección forense de IA generativa

El feedback de campo demostró un gap real: una imagen generada por
Grok (Trump abrazando a Einstein, con texto "I'm a fake image?")
recibió riesgo BAJO-MEDIO porque la herramienta solo tenía evidencia
técnica (ausencia de metadata + ELA limpio + entropía normal). Un
humano la identifica como IA en 2 segundos por el contenido visual.

El gap no se cierra interpretando contenido — eso es clasificación,
no forense. Se cierra agregando técnicas estadísticas que detecten
patrones de generación de IA observables en los bytes del archivo,
sin depender de bases de datos externas, modelos de ML, ni APIs.

Cuatro adiciones evaluadas contra la premisa de integridad forense.

**1. Análisis de tablas de cuantización JPEG (`core/quantization_analyzer.py`)**

Las cámaras reales usan tablas de cuantización específicas del
fabricante (Canon, Nikon, Samsung tienen tablas distintas y
documentadas). Los generadores de IA (Grok, Midjourney, DALL-E,
Stable Diffusion) usan tablas genéricas o las de la biblioteca
de compresión JPEG que emplean (libjpeg, mozjpeg, Pillow). La
diferencia es observable en los bytes 0xFFC0/0xFFC4 del archivo —
no requiere interpretación subjetiva.

Lo que detectaría: "la tabla de cuantización de esta imagen no
corresponde a ningún fabricante de cámara conocido — corresponde
a [libjpeg estándar / Pillow / mozjpeg]."

**2. Análisis de frecuencia por FFT (`core/frequency_analyzer.py`)**

Las imágenes generadas por IA tienen patrones en el dominio de
frecuencia que las fotos de cámara no tienen — artefactos de la
red neuronal que son invisibles a ojo pero detectables con la
Transformada Rápida de Fourier (FFT). Esto es análisis estadístico
puro, como la entropía de Shannon que ya implementamos.

Lo que detectaría: "el espectro de frecuencia de esta imagen
muestra picos periódicos en [frecuencias] que no son consistentes
con ruido de sensor fotográfico."

**3. Análisis de consistencia de ruido (`core/noise_analyzer.py`)**

Las fotos reales tienen un patrón de ruido del sensor (PRNU —
Photo Response Non-Uniformity) que es consistente en toda la
imagen y característico del sensor físico. Las imágenes de IA no
tienen sensor, así que su "ruido" es sintético y estadísticamente
distinto — usualmente demasiado uniforme o con distribución
diferente entre regiones.

Lo que detectaría: "la distribución de ruido en esta imagen es
[demasiado uniforme / inconsistente entre regiones] — no es
consistente con un sensor fotográfico real."

**4. EntropyProfile — extensión de `core/entropy_analyzer.py`**

El análisis de entropía de v0.2.0 fue diseñado para detectar
manipulación (bloques anómalos). Para IA generativa, la pregunta
correcta no es "¿hay bloques anómalos?" sino "¿cómo se comporta
la distribución en su conjunto?" El módulo existente se extiende
(sin romper los 210 tests) con una segunda capa de análisis:

- **Distribución:** skewness y kurtosis de la entropía por bloques.
  Fotos reales tienen cola larga (kurtosis alta); IA tiende a
  distribución más uniforme (kurtosis baja).
- **Coherencia espacial:** gradiente de entropía entre bloques
  adyacentes. Fotos reales tienen transiciones graduales; IA puede
  ser demasiado suave o artificialmente abrupta.
- **Entropía por canal (R, G, B):** un sensor real tiene ruido
  distinto por canal (azul tiene más ruido en CMOS); IA produce
  los tres canales con calidad estadística similar.
- **Multi-escala (32, 64, 128 px):** mismos datos a tres escalas.
  Si la imagen es real, las distribuciones son proporcionales;
  si es IA, pueden divergir.

Lo que detectaría: "distribución de entropía demasiado uniforme
(kurtosis 2.1 vs 4.5+ esperado en foto real), canales R/G/B
con correlación 0.98 (sensor real produce 0.85-0.92)."

**Descartado explícitamente de este roadmap:**

- **Reconocimiento facial / OCR:** requiere modelos de ML externos
  o APIs. Introduce opacidad — "mi modelo identificó a Einstein"
  no es evidencia forense verificable. Además rompe la premisa
  100% offline si usa APIs en la nube.
- **Base de datos de patrones de generadores de IA:** misma objeción
  que YARA — va stale en semanas (cada actualización de Midjourney
  cambia los patrones), y citar "mi base de datos dice que es Grok"
  sin poder mostrar qué bytes activaron la detección introduce
  opacidad.
- **Detección de anacronismos:** requiere base de conocimiento
  general (quién vivió cuándo). Eso es interpretación de contenido,
  no análisis forense del artefacto digital.
- **Clasificación de contenido visual:** el proyecto analiza la
  imagen como artefacto digital — no interpreta su contenido
  semántico. "¿Qué evidencia técnica tiene esta imagen?" es la
  pregunta correcta, no "¿qué muestra esta imagen?"

---

Vector Telemetry Research © 2026 — SIGNAL. VECTOR. INTELLIGENCE.
