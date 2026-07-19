"""
vtr-forensic-img — Tests rust_bridge.py
tests/test_rust_bridge.py

Cobertura de paths no ejercitados:
  - _find_binary() con env var inválida
  - _find_binary() sin binario disponible (retorna None)
  - parse_binary() cuando binario no existe
  - parse_binary() con timeout, JSON inválido, exit codes 1 y 2
  - merge_rust_findings() con None, con anomalías, con chunks PNG,
    con discrepancia de hash, con markers truncados
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.rust_bridge import (
    _binary_name,
    _is_executable,
    _find_binary,
    parse_binary,
    merge_rust_findings,
    _IS_WINDOWS,
)


# ── Stub de ImageMetadata para merge tests ────────────────────────────────────

@dataclass
class StubSecurity:
    parse_errors: list = field(default_factory=list)
    structurally_anomalous: list = field(default_factory=list)
    oversized_fields: list = field(default_factory=list)
    non_printable_chars_in_fields: list = field(default_factory=list)


@dataclass
class StubMeta:
    sha256: str = ""
    extraction_warnings: list = field(default_factory=list)
    png_text_chunks: dict = field(default_factory=dict)
    security: StubSecurity = field(default_factory=StubSecurity)


# ── Tests: _binary_name ───────────────────────────────────────────────────────

class TestBinaryName:
    def test_linux_no_extension(self):
        with patch("core.rust_bridge._IS_WINDOWS", False):
            from core.rust_bridge import _binary_name
            # Reimportar no cambia el módulo-level var, pero podemos
            # verificar la lógica directamente
            if not _IS_WINDOWS:
                assert _binary_name() == "vtr_image_parser"

    def test_name_is_string(self):
        name = _binary_name()
        assert isinstance(name, str)
        assert "vtr_image_parser" in name


# ── Tests: _is_executable ─────────────────────────────────────────────────────

class TestIsExecutable:
    def test_nonexistent_file(self, tmp_path):
        assert _is_executable(tmp_path / "no_existe") is False

    def test_directory_not_executable(self, tmp_path):
        d = tmp_path / "subdir"
        d.mkdir()
        assert _is_executable(d) is False

    def test_existing_file_on_linux(self, tmp_path):
        if _IS_WINDOWS:
            pytest.skip("Test solo para Linux/macOS")
        f = tmp_path / "test_binary"
        f.write_bytes(b"#!/bin/sh\n")
        f.chmod(0o755)
        assert _is_executable(f) is True

    def test_non_executable_file_on_linux(self, tmp_path):
        if _IS_WINDOWS:
            pytest.skip("Test solo para Linux/macOS")
        f = tmp_path / "test_noexec"
        f.write_bytes(b"data")
        f.chmod(0o644)
        assert _is_executable(f) is False


# ── Tests: _find_binary ──────────────────────────────────────────────────────

class TestFindBinary:
    def test_env_var_inexistente_no_crashea(self):
        with patch.dict(os.environ, {"VTR_RUST_PARSER_BIN": "/no/existe/binario"}, clear=False):
            result = _find_binary()
            # Puede encontrarlo por otro path o retornar None — no debe crashear

    def test_env_var_vacia_ignora(self):
        with patch.dict(os.environ, {"VTR_RUST_PARSER_BIN": ""}, clear=False):
            result = _find_binary()
            # Sin env var, busca en rutas relativas y PATH

    def test_retorna_path_o_none(self):
        result = _find_binary()
        assert result is None or isinstance(result, Path)


# ── Tests: parse_binary ──────────────────────────────────────────────────────

class TestParseBinary:
    def test_sin_binario_retorna_none(self):
        with patch("core.rust_bridge._find_binary", return_value=None):
            result = parse_binary("/tmp/test.jpg")
            assert result is None

    def test_exit_code_1_retorna_none(self, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "IO error"
        mock_result.stdout = ""
        with patch("core.rust_bridge._find_binary", return_value=Path("/fake/binary")):
            with patch("subprocess.run", return_value=mock_result):
                result = parse_binary(tmp_path / "test.jpg")
                assert result is None

    def test_exit_code_2_intenta_parsear_json(self, tmp_path):
        """Exit code 2 = formato no reconocido, pero puede tener JSON parcial."""
        partial_json = json.dumps({"format": "unknown", "hashes": {"sha256": "abc123"}})
        mock_result = MagicMock()
        mock_result.returncode = 2
        mock_result.stderr = ""
        mock_result.stdout = partial_json
        with patch("core.rust_bridge._find_binary", return_value=Path("/fake/binary")):
            with patch("subprocess.run", return_value=mock_result):
                result = parse_binary(tmp_path / "test.jpg")
                assert result is not None
                assert result["format"] == "unknown"

    def test_stdout_vacio_retorna_none(self, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_result.stdout = ""
        with patch("core.rust_bridge._find_binary", return_value=Path("/fake/binary")):
            with patch("subprocess.run", return_value=mock_result):
                result = parse_binary(tmp_path / "test.jpg")
                assert result is None

    def test_json_invalido_retorna_none(self, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_result.stdout = "esto no es JSON {{{{"
        with patch("core.rust_bridge._find_binary", return_value=Path("/fake/binary")):
            with patch("subprocess.run", return_value=mock_result):
                result = parse_binary(tmp_path / "test.jpg")
                assert result is None

    def test_timeout_retorna_none(self, tmp_path):
        import subprocess
        with patch("core.rust_bridge._find_binary", return_value=Path("/fake/binary")):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="test", timeout=30)):
                result = parse_binary(tmp_path / "test.jpg")
                assert result is None

    def test_excepcion_generica_retorna_none(self, tmp_path):
        with patch("core.rust_bridge._find_binary", return_value=Path("/fake/binary")):
            with patch("subprocess.run", side_effect=OSError("permission denied")):
                result = parse_binary(tmp_path / "test.jpg")
                assert result is None

    def test_json_valido_retorna_dict(self, tmp_path):
        expected = {"format": "JPEG", "hashes": {"sha256": "abc"}, "anomalies": []}
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_result.stdout = json.dumps(expected)
        with patch("core.rust_bridge._find_binary", return_value=Path("/fake/binary")):
            with patch("subprocess.run", return_value=mock_result):
                result = parse_binary(tmp_path / "test.jpg")
                assert result == expected


# ── Tests: merge_rust_findings ────────────────────────────────────────────────

class TestMergeRustFindings:
    def test_none_result_retorna_inmediato(self):
        meta = StubMeta()
        merge_rust_findings(meta, None)
        assert len(meta.extraction_warnings) == 0

    def test_hash_discrepancia_registrada(self):
        meta = StubMeta(sha256="aaa")
        rust_result = {"hashes": {"sha256": "bbb"}, "anomalies": []}
        merge_rust_findings(meta, rust_result)
        assert len(meta.security.structurally_anomalous) == 1
        assert "DISCREPANCIA" in meta.security.structurally_anomalous[0]

    def test_hash_coincide_no_registra(self):
        meta = StubMeta(sha256="aaa")
        rust_result = {"hashes": {"sha256": "aaa"}, "anomalies": []}
        merge_rust_findings(meta, rust_result)
        assert len(meta.security.structurally_anomalous) == 0

    def test_anomalia_high_va_a_structurally_anomalous(self):
        meta = StubMeta()
        rust_result = {
            "hashes": {},
            "anomalies": [
                {"severity": "HIGH", "category": "structure", "description": "trailing bytes", "byte_offset": 0x1000}
            ],
        }
        merge_rust_findings(meta, rust_result)
        assert len(meta.security.structurally_anomalous) == 1
        assert "0x1000" in meta.security.structurally_anomalous[0]

    def test_anomalia_medium_va_a_warnings(self):
        meta = StubMeta()
        rust_result = {
            "hashes": {},
            "anomalies": [
                {"severity": "MEDIUM", "category": "metadata", "description": "campo sospechoso"}
            ],
        }
        merge_rust_findings(meta, rust_result)
        assert len(meta.extraction_warnings) == 1

    def test_parse_warnings_agregados(self):
        meta = StubMeta()
        rust_result = {
            "hashes": {},
            "anomalies": [],
            "parse_warnings": ["marker truncado", "CRC check skipped"],
        }
        merge_rust_findings(meta, rust_result)
        assert len(meta.extraction_warnings) == 2

    def test_png_chunk_nuevo_agregado(self):
        meta = StubMeta()
        rust_result = {
            "hashes": {},
            "anomalies": [],
            "png": {
                "chunks": [
                    {"text_content": {"key": "Author", "value": "VTR"}, "crc_valid": True}
                ]
            },
        }
        merge_rust_findings(meta, rust_result)
        assert meta.png_text_chunks["Author"] == "VTR"

    def test_png_chunk_existente_no_sobreescrito(self):
        meta = StubMeta(png_text_chunks={"Author": "Python"})
        rust_result = {
            "hashes": {},
            "anomalies": [],
            "png": {
                "chunks": [
                    {"text_content": {"key": "Author", "value": "Rust"}, "crc_valid": True}
                ]
            },
        }
        merge_rust_findings(meta, rust_result)
        assert meta.png_text_chunks["Author"] == "Python"  # no sobreescrito

    def test_png_chunk_valor_none_registra_warning(self):
        meta = StubMeta()
        rust_result = {
            "hashes": {},
            "anomalies": [],
            "png": {
                "chunks": [
                    {"text_content": {"key": "Comment", "value": None}, "crc_valid": True}
                ]
            },
        }
        merge_rust_findings(meta, rust_result)
        assert any("valor ausente" in w for w in meta.extraction_warnings)

    def test_png_crc_invalido_es_anomalia_estructural(self):
        meta = StubMeta()
        rust_result = {
            "hashes": {},
            "anomalies": [],
            "png": {
                "chunks": [
                    {"text_content": {"key": "XMP", "value": "data"}, "crc_valid": False, "offset": 1024}
                ]
            },
        }
        merge_rust_findings(meta, rust_result)
        assert any("CRC inválido" in a for a in meta.security.structurally_anomalous)

    def test_jpeg_marker_truncado_registra_warning(self):
        meta = StubMeta()
        rust_result = {
            "hashes": {},
            "anomalies": [],
            "jpeg": {
                "trailing_bytes": 0,
                "markers_found": [
                    {"marker": "APP1", "truncated": True, "offset": 512,
                     "declared_length": 200, "actual_bytes_available": 50}
                ]
            },
        }
        merge_rust_findings(meta, rust_result)
        assert any("truncado" in w for w in meta.extraction_warnings)

    def test_jpeg_trailing_bytes_no_duplica(self):
        """trailing_bytes > 0 ya está en anomalies[], no se duplica aquí."""
        meta = StubMeta()
        rust_result = {
            "hashes": {},
            "anomalies": [
                {"severity": "HIGH", "category": "structure", "description": "trailing bytes: 100"}
            ],
            "jpeg": {"trailing_bytes": 100, "markers_found": []},
        }
        merge_rust_findings(meta, rust_result)
        # Solo 1 entrada de trailing bytes (de anomalies[]), no duplicada
        trailing_count = sum(1 for a in meta.security.structurally_anomalous if "trailing" in a.lower())
        assert trailing_count == 1

    def test_resultado_vacio_sin_efecto(self):
        meta = StubMeta()
        rust_result = {"hashes": {}, "anomalies": []}
        merge_rust_findings(meta, rust_result)
        assert len(meta.extraction_warnings) == 0
        assert len(meta.security.structurally_anomalous) == 0
