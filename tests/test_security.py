from __future__ import annotations

import os
import socket
import zipfile
from pathlib import Path

import pytest

from quantumguard import audit


def test_oversized_file_is_skipped_without_crash(tmp_path: Path) -> None:
    (tmp_path / "large.py").write_text("x = 1\n" * 100, encoding="utf-8")
    result = audit(tmp_path, max_file_bytes=16)
    assert result.files_analyzed == 0
    assert result.limits["skipped"]["too_large"] == 1


def test_exact_file_size_limit_is_inclusive(tmp_path: Path) -> None:
    path = tmp_path / "exact.py"
    content = b"x = 1\n"
    path.write_bytes(content)
    (tmp_path / "over.py").write_bytes(content + b"#")
    result = audit(tmp_path, max_file_bytes=len(content))
    assert result.files_analyzed == 1
    assert result.bytes_analyzed == len(content)
    assert result.limits["skipped"]["too_large"] == 1


def test_exact_total_bytes_limit_is_inclusive(tmp_path: Path) -> None:
    first = tmp_path / "first.py"
    second = tmp_path / "second.py"
    first.write_bytes(b"x = 1\n")
    second.write_bytes(b"y = 2\n")
    total = first.stat().st_size + second.stat().st_size
    (tmp_path / "over.py").write_bytes(b"z = 3\n")
    result = audit(tmp_path, max_total_bytes=total)
    assert result.files_analyzed == 2
    assert result.bytes_analyzed == total
    assert result.limits["skipped"]["byte_limit"] == 1


def test_exact_file_count_limit_is_inclusive(tmp_path: Path) -> None:
    (tmp_path / "first.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "second.py").write_text("y = 2\n", encoding="utf-8")
    (tmp_path / "over.py").write_text("z = 3\n", encoding="utf-8")
    result = audit(tmp_path, max_files=2)
    assert result.files_analyzed == 2
    assert result.limits["skipped"]["file_limit"] == 1


def test_stat_permission_error_is_skipped_without_crash(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "blocked-stat.py"
    path.write_text("x = 1\n", encoding="utf-8")
    original_stat = Path.stat

    def deny_stat(candidate: Path, *args, **kwargs):
        if candidate == path:
            raise PermissionError("stat denied")
        return original_stat(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", deny_stat)
    result = audit(tmp_path)
    assert result.files_analyzed == 0
    assert result.limits["skipped"]["permission"] == 1


def test_read_permission_error_is_skipped_without_crash(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "blocked-read.py"
    path.write_text("x = 1\n", encoding="utf-8")
    from quantumguard import util

    original_read = util.safe_read_text

    def deny_read(candidate: Path, max_bytes: int) -> str | None:
        if candidate == path:
            raise PermissionError("read denied")
        return original_read(candidate, max_bytes)

    monkeypatch.setattr(util, "safe_read_text", deny_read)
    result = audit(tmp_path)
    assert result.files_analyzed == 0
    assert result.limits["skipped"]["permission"] == 1


def test_symlink_escape_is_not_scanned(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text(
        'import jwt\njwt.encode({}, "key", algorithm="RS256")\n',
        encoding="utf-8",
    )
    link = tmp_path / "escape.py"
    try:
        os.symlink(outside, link)
    except OSError:
        pytest.skip("symlink creation is not available")
    result = audit(tmp_path)
    assert result.findings == []
    assert result.limits["skipped"]["symlink"] == 1


def test_symlink_scan_root_is_rejected(tmp_path: Path) -> None:
    root_link = tmp_path.parent / f"{tmp_path.name}-root-link"
    try:
        os.symlink(tmp_path, root_link)
    except OSError:
        pytest.skip("symlink creation is not available")
    with pytest.raises(ValueError, match="must not be a symlink"):
        audit(root_link)


def test_symlink_directory_loop_and_broken_symlink_are_not_followed(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "danger.py").write_text(
        'import jwt\njwt.encode({}, "key", algorithm="RS256")\n', encoding="utf-8"
    )
    try:
        os.symlink(outside, tmp_path / "outside-dir")
        os.symlink(tmp_path, tmp_path / "self-loop")
        os.symlink(tmp_path / "missing.py", tmp_path / "broken.py")
    except OSError:
        pytest.skip("symlink creation is not available")
    result = audit(tmp_path)
    assert result.findings == []
    assert result.limits["skipped"]["symlink"] == 3


def test_fifo_is_not_opened_or_read(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is not available")
    fifo = tmp_path / "blocking.py"
    try:
        os.mkfifo(fifo)
    except OSError:
        pytest.skip("FIFO creation is not available")
    result = audit(tmp_path)
    assert result.findings == []
    assert result.limits["skipped"]["binary"] == 1


def test_unix_socket_is_not_opened_or_read(tmp_path: Path) -> None:
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("Unix domain sockets are not available")
    path = tmp_path / "socket.py"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            server.bind(str(path))
        except OSError:
            pytest.skip("Unix domain socket creation is not available")
        result = audit(tmp_path)
    finally:
        server.close()
        path.unlink(missing_ok=True)
    assert result.findings == []
    assert result.limits["skipped"]["binary"] == 1


def test_binary_archive_unicode_and_deceptive_names_are_inert(tmp_path: Path) -> None:
    (tmp_path / "rsa_notes.py").write_text(
        "# RSA.generate_private_key(public_exponent=65537)\n"
        "message = 'jwt.encode algorithm RS256'\n",
        encoding="utf-8",
    )
    (tmp_path / "加密🔐.py").write_text("value = 'not a crypto call'\n", encoding="utf-8")
    (tmp_path / "binary.py").write_bytes(b"RSA\x00jwt.encode({}, 'key', algorithm='RS256')")
    with zipfile.ZipFile(tmp_path / "archive.zip", "w") as archive:
        archive.writestr("payload.py", "import jwt\njwt.encode({}, 'key', algorithm='RS256')\n")
    result = audit(tmp_path)
    assert result.findings == []
    assert result.limits["skipped"]["binary"] == 1


def test_encoding_policy_is_graceful_and_bom_is_supported(tmp_path: Path) -> None:
    (tmp_path / "bom.py").write_bytes(b"\xef\xbb\xbfvalue = 1\n")
    (tmp_path / "invalid.py").write_bytes(b"value = '\xff'\n")
    (tmp_path / "utf16.py").write_bytes("value = 1\n".encode("utf-16"))
    result = audit(tmp_path)
    assert result.findings == []
    assert result.files_analyzed == 2
    assert result.limits["skipped"]["binary"] == 1


def test_newline_filename_stays_safe_in_structured_output(tmp_path: Path) -> None:
    path = tmp_path / "name\nwith-space.py"
    path.write_text("value = 1\n", encoding="utf-8")
    result = audit(tmp_path)
    assert result.findings == []
    assert result.to_dict()["limits"]["max_file_bytes"] == 2 * 1024 * 1024


def test_malformed_and_deep_ast_inputs_return_bounded_errors(tmp_path: Path) -> None:
    (tmp_path / "malformed.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "deep.py").write_text("x = [" * 500 + "1" + "]" * 500, encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("rsa @ file:///never-install\n", encoding="utf-8")
    result = audit(tmp_path)
    assert len(result.parser_errors) >= 1
    assert result.findings == []


def test_pathological_syntax_and_file_limits_are_bounded(tmp_path: Path) -> None:
    (tmp_path / "deep.py").write_text("x = [" * 1500 + "1" + "]" * 1500, encoding="utf-8")
    (tmp_path / "long-line.py").write_text("x = " + "1" * 20000 + "\n", encoding="utf-8")
    for index in range(12):
        (tmp_path / f"small-{index}.py").write_text("x = 1\n", encoding="utf-8")
    result = audit(tmp_path, max_files=4, max_total_bytes=30)
    assert result.files_analyzed <= 4
    assert result.bytes_analyzed <= 30
    assert result.limits["skipped"]["file_limit"] + result.limits["skipped"]["byte_limit"] >= 1


def test_file_disappearing_before_read_is_graceful(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "vanishing.py"
    path.write_text("x = 1\n", encoding="utf-8")
    from quantumguard import util

    original = util.safe_read_text

    def disappear(candidate: Path, max_bytes: int) -> str | None:
        candidate.unlink()
        return original(candidate, max_bytes)

    monkeypatch.setattr(util, "safe_read_text", disappear)
    result = audit(tmp_path)
    assert result.findings == []
    assert result.files_analyzed == 0
