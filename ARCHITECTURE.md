# ARCHITECTURE.md — vtr-forensic-img

> Documento de decisiones de arquitectura. Cada decisión aquí
> registrada fue tomada explícitamente — no es documentación generada
> post-facto, sino el registro de la evaluación real que llevó a la
> estructura actual.

## 1. Arquitectura híbrida Rust + Python

### La pregunta que motivó la evaluación

¿Tiene sentido usar Rust para un pipeline de análisis forense de
imágenes donde el ecosistema Python (Pillow, exifread, numpy) ya
resuelve la mayor parte del problema?

### La evaluación real — no un argumento de venta de Rust

**Lo que Rust resuelve que Python no puede garantizar:**

El boundary más relevante es el parser de binarios no confiables.
Una imagen puede ser construida maliciosamente para explotar parsers
de metadata — CVEs históricos en `libexif` y Pillow demuestran que
este no es un riesgo teórico. En Python, el código de parsing de
alto nivel delega eventualmente a C, y las excepciones capturadas
con `except Exception` pueden silenciar condiciones forenses
importantes junto con errores reales de explotación.

En Rust, el borrow checker garantiza en tiempo de compilación la
ausencia de buffer overflows y use-after-free. `Result<T, E>` fuerza
manejo explícito de cada error — no se puede ignorar un fallo de
parsing sin que el compilador lo rechace. Para código que procesa
datos de un adversario potencial, esto es una garantía estructural,
no una práctica.

**Lo que Python tiene que Rust no reemplaza fácilmente:**

El ecosistema de análisis de imagen es maduro en Python — Pillow,
exifread, numpy/scipy para ELA. Reimplementar en Rust introduciría
riesgo de bugs nuevos sin ganancia en la lógica de dominio (los bugs
de lógica —un timestamp interpretado mal, un GPS fuera de rango no
detectado— los tiene cualquier lenguaje). El tiempo de desarrollo
en Rust para la misma funcionalidad de análisis sería sustancialmente
mayor sin beneficio proporcional.

**La conclusión:**

El riesgo real no es uniforme en el pipeline. Es mayor donde hay
bytes crudos no confiables y menor donde hay lógica de dominio sobre
datos ya estructurados. La arquitectura correcta no es "todo Rust"
ni "todo Python" — es asignar cada responsabilidad al lenguaje que
la resuelve mejor.

### El boundary exacto

```
Imagen (bytes no confiables)
         ↓
┌────────────────────────────────────────────┐
│  RUST — rust_parser/src/main.rs            │
│                                            │
│  Responsabilidad:                          │
│  • Detección de formato por firma real     │
│    (no por extensión de archivo)           │
│  • SHA-256 + MD5 para cadena de custodia   │
│  • Parser JPEG: markers, longitudes,       │
│    offsets exactos, trailing bytes         │
│  • Parser PNG: CRC32 por chunk, textos,    │
│    post-IEND data                          │
│                                            │
│  Garantías del compilador:                 │
│  • Sin buffer overflow posible             │
│  • Sin use-after-free posible              │
│  • Cada error es Result::Err explícito     │
│                                            │
│  Output: JSON a stdout, una línea          │
└─────────────────┬──────────────────────────┘
                  │ JSON bien tipado
                  │ (datos ya validados,
                  │  sin bytes crudos)
┌─────────────────▼──────────────────────────┐
│  PYTHON — core/rust_bridge.py              │
│                                            │
│  Responsabilidad:                          │
│  • Invocar el binario Rust                 │
│  • Verificar exit code y parsear JSON      │
│  • Verificar consistencia de hashes        │
│    entre Rust y Python                     │
│  • merge_rust_findings(): agrega           │
│    hallazgos sin sobreescribir Python      │
└─────────────────┬──────────────────────────┘
                  │
┌─────────────────▼──────────────────────────┐
│  PYTHON — pipeline de análisis             │
│                                            │
│  • metadata_extractor.py: EXIF/XMP/GPS     │
│  • ela_analyzer.py: Error Level Analysis   │
│  • consistency_checker.py: hallazgos       │
│  • provenance_report.py: reporte final     │
└────────────────────────────────────────────┘
```

### La interface de comunicación Rust↔Python

**Decisión: stdout JSON, no FFI.**

FFI (ctypes, PyO3) hubiera requerido manejar lifetimes de Rust
cruzando la frontera del lenguaje — complejidad real sin beneficio
proporcional para este caso de uso. El boundary de texto (JSON a
stdout) es auditablemente simple: cualquier auditor puede correr el
binario Rust directamente y verificar su output sin entender Python.
Esta auditabilidad independiente fue el criterio decisivo.

```bash
# El binario Rust es auditable de forma completamente independiente
./rust_parser/target/release/vtr_image_parser imagen.jpg | python3 -m json.tool
```

### Fallback graceful

Si el binario Rust no está disponible:

```
rust_bridge.py → _find_binary() → None
              → log.info("binario no encontrado")
              → retorna None a merge_rust_findings()
              → merge_rust_findings(meta, None) → return inmediato
              → pipeline Python continúa sin interrupción
              → reporte incluye nota de que Rust no estaba disponible
```

"Ausente y registrado" es distinto de "ausente silenciosamente" —
la misma premisa que aplica a los campos de metadata.

---

## 2. Principios de diseño que aplican a todo el código

### None es distinto de ""

Un campo de metadata ausente y un campo presente con valor vacío son
estados forenses distintos. Ninguno se colapsa en el otro.

```python
# Correcto — preserva la distinción
value: Optional[str] = None  # ausente
value: str = ""              # presente pero vacío
```

```rust
// Correcto — el tipo lo garantiza
value: Option<String>  // None = ausente, Some("") = presente vacío
```

### Cada error se registra con contexto específico

Nunca `except Exception: pass`. Cada campo que falla se registra
con el nombre del campo, el tipo de error, y los primeros N bytes
del valor que causó el problema — información que un auditor necesita
para reproducir el hallazgo.

```python
# Incorrecto
try:
    meta.device.make = str(tags.get('Image Make'))
except:
    pass  # silencioso

# Correcto
try:
    val = tags.get('Image Make')
    if val is not None:
        meta.device.make = _safe_str(val, 'Image Make', meta.security)
except Exception as e:
    meta.security.parse_errors.append(f"Image Make: {str(e)[:100]}")
```

### El umbral de análisis siempre se documenta en el output

Cualquier parámetro configurable que afecte el resultado del análisis
aparece en el reporte — no solo el resultado. Un auditor que recibe
un reporte debe poder reproducir el análisis o cuestionar los
parámetros sin tener que leer el código fuente.

### Sanitización defensiva en el boundary de entrada

Todo valor de metadata pasa por `_safe_str()` antes de procesarse:
- Truncado a `MAX_FIELD_LENGTH = 2048` chars
- Caracteres no imprimibles reemplazados por `\xNN` (visibles, no eliminados)
- Nunca `eval()`, `exec()`, ni `subprocess` con datos de metadata

En Rust, la función equivalente `sanitize_bytes()` aplica el mismo
principio: los bytes no-ASCII-printable se representan como `\xNN`,
sin eliminarlos, porque su presencia puede ser información forense.

---

## 3. Hallazgos reales durante el desarrollo

Estos son bugs reales encontrados y corregidos durante la
construcción — no se documentan para justificar el trabajo, sino
porque un auditor futuro necesita saber qué fue verificado y cómo.

### Bug real #1 — SOS marker en el parser JPEG de Rust

**Síntoma:** el parser Rust reportaba 7,606 bytes de "trailing data"
en una imagen JPEG limpia donde Python confirmaba que no había ninguno.

**Causa:** el marker SOS (Start of Scan, 0xDA) tiene una longitud
declarada que cubre solo su header (12 bytes en este caso), pero el
payload del scan data — los datos comprimidos de imagen reales —
no tiene longitud declarada. Se extiende hasta el siguiente marker
real (0xFFD9, EOI). El parser original leía el header SOS, avanzaba
12 bytes, y dejaba `last_end` en el final del header en vez del
final del EOI — reportando todo el scan data como "trailing bytes".

**Verificación cruzada que lo expuso:** Python calculó 0 bytes de
trailing data; Rust calculó 7,606. La discrepancia entre dos parsers
independientes del mismo archivo es exactamente para lo que existe
la verificación cruzada de hashes — si ambos hubieran dado el mismo
número incorrecto, el bug habría pasado desapercibido.

**Corrección:** consumo explícito del scan data byte por byte hasta
encontrar el próximo marker real (0xFF seguido de algo distinto de
0x00 y 0xFF).

### Bug real #2 — Hallazgos duplicados en consistency_checker.py

**Síntoma:** un mismo software de IA aparecía dos veces en los
hallazgos — una por `device.software` y otra por
`editing.software_used`, porque ambos eran iterados en el mismo loop.

**Corrección:** `set(all_software)` antes de iterar, eliminando
duplicados antes de comparar contra la lista de marcadores de IA.

---

## 4. Qué no está implementado en v0.1.0

| Componente | Estado | Nota |
|---|---|---|
| Interfaz web (FastAPI + HTML) | Planificado v0.2.0 | La imagen ELA ya se genera como bytes en `ela_analyzer.py` — lista para incrustar en HTML como base64 |
| Tests formales pytest | Planificado v0.2.0 | El pipeline fue probado manualmente contra 3 escenarios reales |
| Parser WEBP/GIF/TIFF/RAW en Rust | Planificado v0.2.0 | El binario Rust detecta estos formatos por firma y los reporta honestamente como "sin parser específico" |
| Análisis estegonográfico (LSB) | Fuera de alcance v0.1.0 | Requiere análisis estadístico de distribución de bits — distinto del análisis de metadata |
| APIs externas de detección de IA | Decisión permanente: NO | Rompe la cadena de custodia forense — ver sección 1 |

---

Vector Telemetry Research © 2026 — SIGNAL. VECTOR. INTELLIGENCE.
