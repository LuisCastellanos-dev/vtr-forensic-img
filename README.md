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

## Estado actual (v0.1.0 — operativo)

| Componente | Estado |
|---|---|
| Parser binario Rust (JPEG/PNG) | ✅ Operativo |
| Extracción de metadata EXIF/XMP/GPS | ✅ Operativo |
| Error Level Analysis (ELA) | ✅ Operativo |
| Detección de señales de IA generativa | ✅ Operativo |
| Consistency checker forense | ✅ Operativo |
| Interfaz web FastAPI | ✅ Operativo |
| Suite adversarial pytest (55 tests) | ✅ Operativo |
| Parser WEBP/GIF/TIFF/RAW en Rust | 🔲 Detecta formato, no parsea internamente |

## Roadmap v0.2.0

Cuatro adiciones aprobadas. Cada propuesta fue evaluada contra la
premisa de integridad forense — solo se incorpora lo que agrega valor
trazable, sin inferencias ni dependencias cruzadas entre proyectos VTR.

**1. Modo Estricto vs. Modo Forense (`--strict`)**

El parser actual opera en modo forense implícito: cuando encuentra
una anomalia, intenta continuar y recuperar el resto de la estructura,
registrando el offset del error. Un flag `--strict` permitira que el
analista decida que el analisis se detenga al primer error estructural
— util cuando la integridad del archivo es la pregunta principal y
cualquier continuacion pasaria informacion a traves de datos potencialmente
corruptos.

```bash
# Modo forense (actual, default): continua tras errores, los registra
python3 cli.py analyze imagen.jpg

# Modo estricto (v0.2.0): se detiene al primer error estructural
python3 cli.py analyze imagen.jpg --strict
```

**2. Analisis de Entropia por Bloques (`core/entropy_analyzer.py`)**

Complementa ELA con una tecnica distinta: calcular la entropia de
Shannon por bloques de la imagen. Regiones manipuladas suelen mostrar
entropia anomala respecto al fondo — ya sea demasiado baja (area
clonada/copiada con poca variacion) o demasiado alta (datos cifrados
o comprimidos insertados). La distincion con ELA es importante: ELA
detecta diferencias en nivel de compresion JPEG; el analisis de entropia
detecta aleatoriedad de bits — son senales distintas y complementarias.

**3. Verificacion de firma Ed25519 (`core/signature_verifier.py`)**

Permite verificar que una imagen fue firmada criptograficamente por
el dispositivo que afirma haberla capturado, convirtiendo la cadena de
custodia de "confiamos en que nadie la modifico" a "matematicamente
demostrable que no fue modificada desde la captura".

Decision arquitectonica — sin inferencias: este modulo implementa la
verificacion de firmas Ed25519 usando PyNaCl (misma biblioteca ya
evaluada contra CVE-2025-69277, misma restriccion de version >= 1.6.2)
sin importar ningun codigo de vtr-continuity. El dispositivo que captura
la imagen firma con su llave privada; vtr-forensic-img verifica contra
la llave publica registrada. La gestion de llaves (PKI de dos niveles,
device_registry.vtrdb) es responsabilidad de vtr-continuity; la
verificacion de firmas es responsabilidad de este proyecto. Sin
dependencias cruzadas.

```bash
# Verificar que imagen.jpg fue firmada por el dispositivo registrado
python3 cli.py analyze imagen.jpg --verify-signature firma.sig --public-key device_pub.key
```

**4. Comparacion diferencial entre dos imagenes (`core/diff_analyzer.py`)**

Compara dos imagenes provistas por el analista — por ejemplo, una
version declarada como "original" y una version sospechosa — e
identifica exactamente donde difieren a nivel de bytes, markers, y
metadata, no solo a nivel de pixeles.

Decision arquitectonica — sin inferencias: este modulo nunca asume la
existencia de una "imagen dorada" o "verdad de fabrica" externa. El
analista provee ambas imagenes explicitamente. Si no existe una version
original verificable, la comparacion no se puede hacer — y el sistema
lo dice claramente en vez de inventar un referente.

```bash
# Comparar imagen sospechosa contra version que el analista declara original
python3 cli.py diff imagen_sospechosa.jpg imagen_original.jpg
```

**Descartado explicitamente de este roadmap:**

- **Importar ed25519_sign.py de vtr-continuity:** viola la regla de
  no mezcla entre repos VTR. La verificacion de firmas se implementa
  de forma independiente con la misma biblioteca.
- **Comparacion contra "imagen dorada" sin proveerla:** asumir que
  existe una verdad de fabrica sin que el analista la provea
  explicitamente introduciria una afirmacion no verificable.
- **YARA pattern matching:** las reglas YARA son mantenidas por
  terceros y no son verificables directamente. Citar "YARA lo detecto"
  en un reporte forense sin mostrar exactamente que bytes activaron que
  regla introduce opacidad que contradice la premisa del proyecto.
- **APIs externas de deteccion de IA:** decision permanente, no
  limitacion tecnica. Rompe la cadena de custodia forense.

## Lo que este proyecto NO hace (v0.1.0)

- No analiza WEBP, GIF, TIFF, o RAW internamente (el parser Rust
  detecta el formato por firma pero no recorre su estructura)
- No usa APIs externas de detección de IA — decisión deliberada,
  documentada en ARCHITECTURE.md

---

Vector Telemetry Research © 2026 — SIGNAL. VECTOR. INTELLIGENCE.
