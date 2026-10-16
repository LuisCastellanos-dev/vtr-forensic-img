# vtr-forensic-img

> Forensic image analysis tool for authenticity auditing, manipulation
> detection, and provenance recovery. Built under the operational
> principles of **Vector Telemetry Research** — every byte declared
> is verified, no null is silently backfilled.

## FreeBSD Port

`security/vtr-forensic-img` has been submitted to FreeBSD Ports as
[Bug 299405](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=299405)
and is awaiting committer review. Once accepted:

```bash
cd /usr/ports/security/vtr-forensic-img && make install clean
```

## What it does

Analyzes an image (local or URL) and produces a forensic report
integrating two streams simultaneously:

**Stream 1 — Authenticity / AI-generated image detection**
- AI generator software markers in metadata (Stable Diffusion,
  Midjourney, DALL-E, and others)
- Structural absence of camera metadata (no manufacturer, model,
  or capture parameters)
- Error Level Analysis (ELA) — anomalous JPEG compression
  distribution indicating localized post-capture editing
- Embedded thumbnail inconsistent with main image (subsequent crop)
- JPEG quantization table fingerprinting — camera vs. AI library
  detection (libjpeg, mozjpeg, Pillow)
- FFT frequency domain analysis — periodic peaks from neural
  network generation artifacts
- PRNU sensor noise consistency — synthetic noise vs. real sensor
  noise distribution
- Multi-scale entropy profiling — skewness, kurtosis, spatial
  gradients, per-channel R/G/B entropy

**Stream 2 — Provenance / genealogical and forensic context**
- Complete EXIF/XMP/IPTC/PNG chunk extraction with exact source
- GPS with physically possible range validation
- Reconstructed timeline: EXIF Original vs. Digitized vs. filesystem
- Capture device identification (manufacturer, model, serial)
- Editing software history

**Binary security layer (Rust)**
- JPEG parser: markers with exact byte offsets, truncation detection,
  trailing bytes past EOI, APP1/COM segments
- PNG parser: CRC32 verified per chunk, post-IEND data, anomalous chunks
- SHA-256 + MD5 for chain of custody, cross-verified with Python

## Repository structure

```
vtr-forensic-img/
├── cli.py                      — command-line interface (--strict, --no-ela, --json)
├── core/
│   ├── __init__.py
│   ├── metadata_extractor.py   — EXIF/XMP/GPS/timestamps (Python)
│   ├── ela_analyzer.py         — Error Level Analysis
│   ├── entropy_analyzer.py     — Shannon entropy by blocks + EntropyProfile v0.3.0
│   ├── quantization_analyzer.py — JPEG DQT tables, IJG vs camera fingerprinting (v0.3.0)
│   ├── frequency_analyzer.py  — FFT spectral analysis, 1/f slope, periodic peaks (v0.3.0)
│   ├── noise_analyzer.py      — PRNU sensor noise consistency (v0.3.0)
│   ├── consistency_checker.py  — forensic findings + AI signals
│   ├── signature_verifier.py   — Ed25519 verification (PyNaCl, no vtr-continuity import)
│   ├── diff_analyzer.py        — differential comparison: binary/metadata/visual
│   ├── strict_mode.py          — strict vs forensic AnalysisContext
│   ├── context_loader.py       — secure external context integration (8 mitigations)
│   ├── provenance_report.py    — final report assembler
│   └── rust_bridge.py          — Python↔Rust bridge (portable Linux/macOS/Windows)
├── rust_parser/
│   ├── Cargo.toml              — Rust dependencies (deliberately minimal)
│   └── src/
│       └── main.rs             — JPEG/PNG binary parser
├── web/
│   ├── app.py                  — FastAPI + strict CSP + localhost only
│   └── _analysis_worker.py     — isolated subprocess per analysis
├── tests/
│   ├── conftest.py             — adversarial fixtures built byte by byte
│   ├── test_metadata_extractor.py
│   ├── test_metadata_extended.py — PNG chunks, thumbnail, GPS full, _safe_str
│   ├── test_consistency_checker.py
│   ├── test_ela_analyzer.py
│   ├── test_v020_modules.py    — strict, entropy, Ed25519, diff
│   ├── test_pipeline_integration.py — provenance_report, generate/to_text/to_json
│   ├── test_rust_bridge.py     — parse_binary, merge_rust_findings, fallbacks
│   └── test_adversarial.py     — pentester/auditor/forensic cross-module
├── README.md
├── ARCHITECTURE.md
└── HARDENING.md
```

## Installation

### Python dependencies

```bash
pip install exifread piexif numpy scipy requests pillow pynacl
```

### Rust parser (recommended, not required)

```bash
cd rust_parser
cargo build --release
export VTR_RUST_PARSER_BIN=$(pwd)/target/release/vtr_image_parser
```

If the Rust binary is not available, the pipeline continues with
Python parsers — explicitly logged in the report, never silently.

### Permanent environment variable

```bash
echo 'export VTR_RUST_PARSER_BIN=~/vtr-forensic-img/rust_parser/target/release/vtr_image_parser' >> ~/.bashrc
```

## Usage

```bash
# Local image
python3 cli.py analyze photo.jpg

# Remote URL
python3 cli.py analyze https://example.com/image.jpg

# JSON output (for automation)
python3 cli.py analyze photo.jpg --json

# Without ELA (faster)
python3 cli.py analyze photo.jpg --no-ela

# Save report
python3 cli.py analyze photo.jpg --output report.txt

# Adjust ELA threshold (default 15.0, scale 0-255)
python3 cli.py analyze photo.jpg --ela-threshold 20

# With external network context (cryptofault integration)
python3 cli.py analyze photo.jpg --context cf_report.json --json
```

**Exit codes** (useful in automated pipelines):
- `0` — analysis completed, risk level LOW
- `1` — risk level LOW-MEDIUM or MEDIUM
- `2` — risk level HIGH

## Sample report

```
VTR FORENSIC IMAGE ANALYZER v0.3.1
File:       DSCN0010.jpg
Analysis:   2026-07-07T00:06:32Z

── DEVICE ─────────────────────────────────────
  Manufacturer: NIKON
  Model:        COOLPIX P6000
  Software:     Nikon Transfer 1.1 W

── GPS ──────────────────────────────────────────
  Latitude:  43.467448
  Longitude: 11.885127        ← Siena, Italy
  Valid:     YES

── ELA ──────────────────────────────────────────
  Mean error:      2.163
  Anomalous blocks: 0.0%
  Confidence:      LOW suspicion of manipulation

── FINDINGS ────────────────────────────────────
  Risk level: LOW
  No inconsistency findings.
```

## Design decisions relevant to an auditor

**100% offline.** No image data is sent to external services. In a
forensic context, sending the image to a third-party service breaks
the chain of custody — the image is the evidence.

**`None` is distinct from `""`.** An absent metadata field and a
field present with an empty value are distinct forensic states.
Neither is silently collapsed into the other.

**The Rust parser verifies CRC32 per PNG chunk.** An invalid CRC
means the chunk data was modified after the file was written — the
report flags it as a HIGH severity anomaly with the exact byte offset.

**ELA is an indicator, not proof.** The report states this explicitly,
including the threshold and recompression quality used, so any auditor
can reproduce the analysis with the same parameters or challenge them.

## Current status (v0.3.1 — operational)

| Component | Status | Tests |
|---|---|---|
| Rust binary parser (JPEG/PNG) | ✅ Operational | 30 (rust_bridge) |
| EXIF/XMP/GPS metadata extraction | ✅ Operational | 41 (extractor + extended) |
| Error Level Analysis (ELA) | ✅ Operational | 14 |
| AI-generated image signal detection | ✅ Operational | 14 |
| Forensic consistency checker | ✅ Operational | 13 |
| FastAPI web interface (localhost, CSP) | ✅ Operational | — |
| Strict mode `--strict` | ✅ v0.2.0 | 10 |
| Shannon entropy + EntropyProfile | ✅ v0.3.0 | 10 |
| Ed25519 signature verification | ✅ v0.2.0 | 10 |
| Differential comparison A/B | ✅ v0.2.0 | 12 |
| JPEG quantization tables (DQT) | ✅ v0.3.0 | — |
| FFT frequency analysis | ✅ v0.3.0 | — |
| PRNU noise consistency | ✅ v0.3.0 | — |
| External context integration | ✅ v0.3.1 | 20 |
| Pipeline integration | ✅ v0.2.0 | 28 (provenance_report 87%) |
| Adversarial suite (pentester/auditor/forensic) | ✅ v0.2.0 | 36 |
| Cross-OS portability (Linux/macOS/Windows) | ✅ Applied | — |
| WEBP/GIF/TIFF/RAW Rust parser | 🔲 Detects format, does not parse | — |
| **Total tests** | | **292** |

## What was built in v0.2.0 — and why

Four modules implemented. Each was evaluated against the forensic
integrity premise before approval — only what adds traceable value
was incorporated, with no inferences and no cross-dependencies.

**1. Strict mode vs. Forensic mode (`--strict`)**

`core/strict_mode.py` — centralized `AnalysisContext` that decides
in one place whether to log an error or raise `StrictModeViolation`.
Exit code 3 for strict mode violations. No scattered `if/else` —
parsing functions call `ctx.record_error()` without knowing which
mode they are in.

```bash
python3 cli.py analyze image.jpg --strict
```

**2. Shannon entropy by blocks (`core/entropy_analyzer.py`)**

Complements ELA: detects bit randomness (encrypted or steganographic
data inserted) vs. cloned regions (anomalously low entropy). Includes
explicit caveats and parameters logged in output.

**3. Ed25519 signature verification (`core/signature_verifier.py`)**

Cryptographic chain of custody verification — PyNaCl directly, without
importing code from vtr-continuity. A single modified byte invalidates
the signature. Includes `sign_image()` for testing and
`verify_signature()` for auditing.

**4. Differential comparison (`core/diff_analyzer.py`)**

Three levels: binary (offset of first difference, distinct bytes),
metadata (EXIF fields changed/added/removed), visual (distinct pixels
with ratio). Never assumes a "golden image" — the analyst provides
both images explicitly.

**Cross-OS portability (commit f1a618b)**

`rust_bridge.py` detects binary name by OS (`.exe` on Windows),
`_is_executable()` without `os.X_OK` on Windows, `tempfile.mkstemp()`
instead of `NamedTemporaryFile`, `shell=False` documented explicitly.

## What was built in v0.3.0 — AI-generated image forensic detection

Field feedback exposed a real gap: an AI-generated image (Trump
hugging Einstein, with text "I'm a fake image?") received LOW-MEDIUM
risk because the tool only had technical evidence (absent metadata +
clean ELA + normal entropy). A human identifies it as AI in 2 seconds
by visual content.

The gap is not closed by interpreting content — that is classification,
not forensics. It is closed by adding statistical techniques that
detect AI generation patterns observable in the file's bytes, without
depending on external databases, ML models, or APIs.

Four modules implemented:

**1. JPEG quantization table analysis (`core/quantization_analyzer.py`)**

Real cameras use manufacturer-specific quantization tables (Canon,
Nikon, Samsung have distinct, documented tables). AI generators
(Grok, Midjourney, DALL-E, Stable Diffusion) use generic tables or
those from whatever JPEG compression library they use (libjpeg,
mozjpeg, Pillow). The difference is observable in bytes 0xFFC0/0xFFC4
— no subjective interpretation required.

**2. FFT frequency analysis (`core/frequency_analyzer.py`)**

AI-generated images have frequency-domain patterns that camera photos
do not — neural network artifacts that are invisible to the eye but
detectable with the Fast Fourier Transform (FFT). Pure statistical
analysis, like the Shannon entropy already implemented.

**3. Noise consistency analysis (`core/noise_analyzer.py`)**

Real photos have a sensor noise pattern (PRNU — Photo Response
Non-Uniformity) that is consistent across the entire image and
characteristic of the physical sensor. AI images have no sensor, so
their "noise" is synthetic and statistically distinct — usually too
uniform or with different distribution between regions.

**4. EntropyProfile — extension of `core/entropy_analyzer.py`**

The v0.2.0 entropy analysis was designed to detect manipulation
(anomalous blocks). For AI generation, the right question is not
"are there anomalous blocks?" but "how does the distribution behave
as a whole?" The existing module is extended (without breaking
existing tests) with a second analysis layer:

- **Distribution:** skewness and kurtosis of entropy by blocks.
  Real photos have a long tail (high kurtosis); AI tends toward
  more uniform distribution (low kurtosis).
- **Spatial coherence:** entropy gradient between adjacent blocks.
  Real photos have gradual transitions; AI can be too smooth or
  artificially abrupt.
- **Per-channel entropy (R, G, B):** a real sensor has different
  noise per channel (blue has more noise in CMOS); AI produces
  all three channels with similar statistical quality.
- **Multi-scale (32, 64, 128 px):** same data at three scales.
  If the image is real, distributions are proportional; if AI,
  they may diverge.

## Decisions discarded — with documented rationale

- **Importing `ed25519_sign.py` from vtr-continuity:** violates
  the no-mixing rule between VTR repositories.
- **Comparison against a "golden image" without providing one:**
  assuming a factory truth without the analyst providing it is an
  unverifiable assertion.
- **YARA pattern matching:** third-party rules not directly
  verifiable. Opacity incompatible with the project premise.
- **External AI detection APIs:** permanent decision. Breaks
  forensic chain of custody.
- **Facial recognition / OCR:** requires external ML models or
  APIs. Introduces opacity — "my model identified Einstein" is
  not verifiable forensic evidence. Also breaks the 100% offline
  premise if using cloud APIs.
- **AI generator pattern database:** same objection as YARA —
  goes stale in weeks (every Midjourney update changes patterns),
  and citing "my database says it's Grok" without showing which
  bytes triggered the detection introduces opacity.
- **Anachronism detection:** requires general knowledge base
  (who lived when). That is content interpretation, not forensic
  analysis of the digital artifact.
- **Visual content classification:** the project analyzes the
  image as a digital artifact — it does not interpret its semantic
  content.

## What this project does NOT do (v0.3.1)

- Does not parse WEBP, GIF, TIFF, or RAW internally (the Rust
  parser detects the format by signature but does not walk its
  structure)
- Does not use external AI detection APIs — deliberate decision,
  documented in ARCHITECTURE.md
- Does not interpret the visual content of the image (does not
  recognize people, does not read embedded text, does not detect
  anachronisms)

## Hardening

See [HARDENING.md](HARDENING.md) for the full security hardening
posture, planned improvements, and verification procedures.

---

## VTR Ecosystem Integration

`vtr-forensic-img` integrates with [cryptofault](https://github.com/LuisCastellanos-dev/cryptofault) as part of the VTR toolchain.

### Level 1 Pipeline — Network + Forensic correlation

```sh
# Step 1 — cryptofault analyzes network traffic
cryptofault scan --pcap capture.pcap --format json > cf_report.json

# Step 2 — vtr-forensic-img analyzes image with network context
python3 cli.py analyze image.jpg --context cf_report.json --json > forensic_report.json
```

The `--context` flag embeds cryptofault findings into the forensic report
under `external_context`. The context is always marked `context_unverified: true`
and never affects the forensic analysis chain of custody.

**Security constraints:** max 50KB, `.json` extension required, max nesting
depth 5 levels. A warning is printed when network context is added to a
forensic report.

---

Vector Telemetry Research | SIGNAL. VECTOR. INTELLIGENCE.
