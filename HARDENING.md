# Hardening

> Security hardening posture for vtr-forensic-img — what is already in
> place, what is planned, and how to verify it.

## What is already hardened

### 1. Supply chain — offline vendored build

All 23 Rust crates are vendored via the FreeBSD ports `CARGO_CRATES`
mechanism. The build never fetches dependencies at compile time —
every crate is verified against the SHA-256 hashes in `distinfo`.
A MITM during a `poudriere` build cannot inject code because there
is no network fetch to intercept.

### 2. Memory safety — Rust binary parser

The JPEG/PNG parser is written in Rust, eliminating the most common
classes of C vulnerabilities: buffer overflows, use-after-free, and
format string attacks. A maliciously crafted image that would give
an attacker RCE against a C parser will, at worst, trigger a panic
in Rust — a controlled abort, not arbitrary code execution.

### 3. No magic verdicts — legal hardening

The tool never outputs "this image is fake with 98% confidence."
Every finding is a measurable observation: a CRC mismatch at byte
offset N, an entropy value outside the expected range, a
quantization table that matches libjpeg rather than a camera
manufacturer. This protects both the analyst and the tool from
accusations of false certainty in legal proceedings.

## Planned hardening improvements

### A. Rust compiler hardening

| Measure | Purpose | Status |
|---|---|---|
| `RUSTFLAGS="-D warnings"` | Treat all warnings as errors — no silent issues in CI | Planned |
| `#![deny(unsafe_code)]` in parser | Reject any `unsafe` block unless explicitly audited | Planned |
| `panic = "abort"` in release profile | No stack unwinding — if evidence is invalid, abort cleanly | Planned |
| `max_alloc = 100MB` per image | Prevent DoS from images declaring absurd dimensions | Planned |

### B. FreeBSD port hardening

| Measure | Purpose | Status |
|---|---|---|
| Verify PIE/RELRO with `hardening-check` or `readelf -l` | Confirm position-independent executable and read-only relocations | Planned |
| `STRIP=yes` for release binaries | Remove symbol tables — less information for an attacker | Planned |
| Verify no SUID installation | The tool never needs root privileges | Planned |

### C. Forensic workflow hardening

| Measure | Purpose | Status |
|---|---|---|
| W^X for reports: `vtr-forensic-img verify report.json --pubkey` | Report immutability — Ed25519 signature invalidates any post-creation edit | Planned |
| Determinism test (test 293) | Same image analyzed twice must produce byte-identical SHA-256 of the report | Planned |
| Malicious corpus (`tests/corpus-malicious/`) | Fuzzed images via `cargo fuzz` — test what *invalid* input does, not just valid | Planned |

## Verification

Run these three commands against the release binary:

```bash
# 1. Check binary hardening (PIE, RELRO, stack canary)
hardening-check ./target/release/vtr_image_parser

# 2. Audit dependencies for known vulnerabilities
cargo audit

# 3. Check license and ban policy compliance
cargo deny check
```

If all three pass clean, the following statement is verifiable:

> Hardened build, no unsafe code, offline dependencies,
> deterministic reports.

For a CISO at a port terminal in Altamira, that translates to:
"I can carry this USB to a forensic examination and defend it."

## Determinism requirement

A forensic tool must be deterministic. Running the analysis twice
on the same image must produce a report with an identical SHA-256
hash. If it does not, the report is not defensible in court.

```bash
# Verify determinism
python3 cli.py analyze image.jpg --json > /tmp/report1.json
python3 cli.py analyze image.jpg --json > /tmp/report2.json
sha256 /tmp/report1.json /tmp/report2.json
# Both hashes must match
```

This will be enforced as an automated test (`test_report_determinism`)
in the test suite.

## Malicious input corpus

The current 292 tests verify correct behavior on valid and edge-case
input. What is missing is a corpus of intentionally malformed images
designed to break the parser:

- Truncated JPEG mid-marker
- PNG with invalid CRC in every chunk
- JPEG with dimensions claiming 65535 x 65535 pixels
- Nested EXIF pointing to itself (infinite loop)
- APP1 segment larger than the file
- Zero-length image data after SOF

These will live in `tests/corpus-malicious/` and be generated with
`cargo fuzz`. The goal is not 100% coverage of invalid input — it is
proof that the parser fails safely (panic or controlled error) rather
than unsafely (memory corruption, hang, or infinite allocation).

---

Vector Telemetry Research | SIGNAL. VECTOR. INTELLIGENCE.
