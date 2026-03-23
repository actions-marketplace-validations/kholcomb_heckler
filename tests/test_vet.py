"""Tests for package vetting."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from heckler.vet import (
    _UnsafeArchiveError,
    _safe_tar_extract,
    _safe_zip_extract,
    _validate_archive_member,
    detect_registry,
    extract_package,
)


class TestDetectRegistry:
    def test_npm_at_version(self) -> None:
        assert detect_registry("express@4.18.0") == "npm"

    def test_npm_scoped(self) -> None:
        assert detect_registry("@babel/core@7.24.0") == "npm"

    def test_pypi_double_equals(self) -> None:
        assert detect_registry("requests==2.31.0") == "pypi"

    def test_pypi_gte(self) -> None:
        assert detect_registry("django>=4.2") == "pypi"

    def test_pypi_compatible(self) -> None:
        assert detect_registry("flask~=3.0") == "pypi"

    def test_unknown_bare_name(self) -> None:
        assert detect_registry("lodash") == "unknown"


class TestValidateArchiveMember:
    def test_rejects_dotdot_traversal(self, tmp_path: Path) -> None:
        resolved = tmp_path.resolve()
        with pytest.raises(_UnsafeArchiveError, match="Path traversal"):
            _validate_archive_member("../../etc/passwd", resolved, tmp_path)

    def test_rejects_absolute_path_escape(self, tmp_path: Path) -> None:
        resolved = tmp_path.resolve()
        with pytest.raises(_UnsafeArchiveError, match="Path escapes"):
            _validate_archive_member("/etc/passwd", resolved, tmp_path)

    def test_allows_normal_path(self, tmp_path: Path) -> None:
        resolved = tmp_path.resolve()
        _validate_archive_member("package/index.js", resolved, tmp_path)

    def test_allows_nested_path(self, tmp_path: Path) -> None:
        resolved = tmp_path.resolve()
        _validate_archive_member("package/src/lib/util.js", resolved, tmp_path)


class TestSafeZipExtract:
    def _make_zip(self, tmp_path: Path, entries: dict[str, bytes]) -> Path:
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            for name, content in entries.items():
                zf.writestr(name, content)
        return zip_path

    def test_normal_zip_extracts(self, tmp_path: Path) -> None:
        zip_path = self._make_zip(tmp_path, {"hello.txt": b"world"})
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        _safe_zip_extract(zip_path, extract_dir, extract_dir.resolve())
        assert (extract_dir / "hello.txt").read_bytes() == b"world"

    def test_rejects_path_traversal_zip(self, tmp_path: Path) -> None:
        zip_path = tmp_path / "evil.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("../../evil.txt", b"gotcha")
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        with pytest.raises(_UnsafeArchiveError, match="Path traversal"):
            _safe_zip_extract(zip_path, extract_dir, extract_dir.resolve())


class TestSafeTarExtract:
    def _make_tar(self, tmp_path: Path, entries: dict[str, bytes]) -> Path:
        tar_path = tmp_path / "test.tar.gz"
        with tarfile.open(tar_path, 'w:gz') as tf:
            for name, content in entries.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(content)
                tf.addfile(info, io.BytesIO(content))
        return tar_path

    def test_normal_tar_extracts(self, tmp_path: Path) -> None:
        tar_path = self._make_tar(tmp_path, {"hello.txt": b"world"})
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        _safe_tar_extract(tar_path, extract_dir, extract_dir.resolve())
        assert (extract_dir / "hello.txt").read_bytes() == b"world"

    def test_rejects_path_traversal_tar(self, tmp_path: Path) -> None:
        tar_path = self._make_tar(tmp_path, {"../../evil.txt": b"gotcha"})
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        with pytest.raises(_UnsafeArchiveError, match="(?i)unsafe|traversal|outside"):
            _safe_tar_extract(tar_path, extract_dir, extract_dir.resolve())

    def test_rejects_symlink_tar(self, tmp_path: Path) -> None:
        tar_path = tmp_path / "symlink.tar.gz"
        with tarfile.open(tar_path, 'w:gz') as tf:
            info = tarfile.TarInfo(name="link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tf.addfile(info)
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()
        with pytest.raises(_UnsafeArchiveError, match="(?i)unsafe|link|absolute"):
            _safe_tar_extract(tar_path, extract_dir, extract_dir.resolve())
