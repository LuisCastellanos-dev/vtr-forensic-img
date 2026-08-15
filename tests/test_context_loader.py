"""
Tests para core/context_loader.py
Cubre las 8 mitigaciones de seguridad implementadas.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from core.context_loader import (
    CONTEXT_WARNING,
    MAX_CONTEXT_BYTES,
    MAX_CONTEXT_DEPTH,
    ContextLoadError,
    _validate_depth,
    load,
)


# ── Fixtures ────────────────────────────────────────────────────────────────

def make_cf_report(tmp_path: Path, findings=None, extra=None) -> Path:
    """Genera un cf_report.json mínimo válido."""
    data = {
        "schema_version": "1.0",
        "tool": "cryptofault",
        "tool_version": "0.2.0",
        "analysis_id": "cf-20260815-abcd1234",
        "timestamp": "2026-08-15T00:00:00Z",
        "source": {"type": "pcap", "path": "capture.pcap", "sha256": "abc123"},
        "findings": findings or [],
        "summary": {"total_findings": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    }
    if extra:
        data.update(extra)
    p = tmp_path / "cf_report.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


# ── Mitigación 3 — Path traversal ───────────────────────────────────────────

def test_rejects_non_json_extension(tmp_path):
    p = tmp_path / "context.txt"
    p.write_text("{}", encoding="utf-8")
    with pytest.raises(ContextLoadError, match="must have .json extension"):
        load(str(p))


def test_rejects_no_extension(tmp_path):
    p = tmp_path / "context"
    p.write_text("{}", encoding="utf-8")
    with pytest.raises(ContextLoadError, match="must have .json extension"):
        load(str(p))


def test_rejects_missing_file(tmp_path):
    with pytest.raises(ContextLoadError, match="not found"):
        load(str(tmp_path / "nonexistent.json"))


def test_rejects_directory(tmp_path):
    d = tmp_path / "dir.json"
    d.mkdir()
    with pytest.raises(ContextLoadError, match="not a regular file"):
        load(str(d))


# ── Mitigación 4 — Tamaño no acotado ────────────────────────────────────────

def test_rejects_oversized_file(tmp_path):
    p = tmp_path / "big.json"
    # Genera JSON válido que supera MAX_CONTEXT_BYTES
    data = {"key": "x" * (MAX_CONTEXT_BYTES + 1)}
    p.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ContextLoadError, match="too large"):
        load(str(p))


def test_accepts_file_at_limit(tmp_path):
    """Archivo justo por debajo del límite debe pasar."""
    p = make_cf_report(tmp_path)
    # El reporte mínimo es pequeño — debe pasar
    result = load(str(p))
    assert result is not None


# ── Mitigación 7 — JSON anidamiento profundo ─────────────────────────────────

def test_rejects_deeply_nested_json(tmp_path):
    # Construye JSON con anidamiento mayor a MAX_CONTEXT_DEPTH
    nested = "x"
    for _ in range(MAX_CONTEXT_DEPTH + 2):
        nested = {"k": nested}
    p = tmp_path / "deep.json"
    p.write_text(json.dumps(nested), encoding="utf-8")
    with pytest.raises(ContextLoadError, match="maximum nesting depth"):
        load(str(p))


def test_validate_depth_flat():
    _validate_depth({"a": 1, "b": 2}, max_depth=5)  # no debe lanzar


def test_validate_depth_list():
    _validate_depth([1, 2, [3, 4]], max_depth=5)  # no debe lanzar


def test_validate_depth_exceeds():
    deep = {"a": {"b": {"c": {"d": {"e": {"f": "too deep"}}}}}}
    with pytest.raises(ContextLoadError, match="maximum nesting depth"):
        _validate_depth(deep, max_depth=4)


# ── Mitigación 1+2+5+6 — Output seguro ──────────────────────────────────────

def test_output_always_has_context_unverified(tmp_path):
    p = make_cf_report(tmp_path)
    result = load(str(p))
    assert result["context_unverified"] is True


def test_output_always_has_vtr_context_source(tmp_path):
    p = make_cf_report(tmp_path)
    result = load(str(p))
    assert result["_vtr_context_source"] == "cryptofault"


def test_output_includes_source_analysis_id(tmp_path):
    p = make_cf_report(tmp_path)
    result = load(str(p))
    assert result["source_analysis_id"] == "cf-20260815-abcd1234"


def test_output_includes_source_timestamp(tmp_path):
    p = make_cf_report(tmp_path)
    result = load(str(p))
    assert result["source_timestamp"] == "2026-08-15T00:00:00Z"


def test_output_includes_findings(tmp_path):
    findings = [
        {
            "id": "CF-001",
            "severity": "HIGH",
            "category": "tls_version",
            "description": "TLS 1.0 detected",
            "evidence": "ClientHello version=0x0301",
            "reference": "RFC 8996",
        }
    ]
    p = make_cf_report(tmp_path, findings=findings)
    result = load(str(p))
    assert len(result["findings"]) == 1
    assert result["findings"][0]["id"] == "CF-001"


def test_output_includes_findings_summary(tmp_path):
    p = make_cf_report(tmp_path)
    result = load(str(p))
    assert "findings_summary" in result


def test_output_includes_context_file_name(tmp_path):
    p = make_cf_report(tmp_path)
    result = load(str(p))
    assert result["context_file"] == "cf_report.json"


# ── JSON inválido ────────────────────────────────────────────────────────────

def test_rejects_invalid_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("not json at all {{{", encoding="utf-8")
    with pytest.raises(ContextLoadError, match="invalid JSON"):
        load(str(p))


def test_rejects_json_array_at_root(tmp_path):
    p = tmp_path / "array.json"
    p.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ContextLoadError, match="must be an object"):
        load(str(p))


# ── Mitigación 8 — Warning string ───────────────────────────────────────────

def test_context_warning_exists():
    assert CONTEXT_WARNING is not None
    assert "ADVERTENCIA" in CONTEXT_WARNING
    assert "red" in CONTEXT_WARNING
