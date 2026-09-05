from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def relative_posix(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def safe_read_text(path: Path, max_bytes: int) -> str | None:
    if max_bytes <= 0:
        return None
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        if path.is_symlink() or not path.is_file():
            return None
        descriptor = os.open(path, flags)
    except PermissionError:
        raise
    except OSError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            return None
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(descriptor, min(65536, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > max_bytes:
                return None
    except PermissionError:
        raise
    except OSError:
        return None
    finally:
        os.close(descriptor)
    if b"\x00" in data[:4096]:
        return None
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
    return text.removeprefix("\ufeff")


def iter_source_files(
    root: Path,
    *,
    extensions: set[str],
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> tuple[list[tuple[Path, str]], dict[str, int]]:
    if root.is_symlink():
        raise ValueError(f"scan root must not be a symlink: {root}")
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"scan root is not a directory: {root}")
    skipped = {
        "symlink": 0,
        "too_large": 0,
        "binary": 0,
        "permission": 0,
        "file_limit": 0,
        "byte_limit": 0,
        "walk_error": 0,
    }
    ignored_dirs = {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        "vendor",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "coverage",
    }
    selected: list[tuple[Path, str]] = []
    total = 0

    def on_walk_error(error: OSError) -> None:
        if isinstance(error, PermissionError):
            skipped["permission"] += 1
        else:
            skipped["walk_error"] += 1

    for current, dirs, filenames in os.walk(
        root, topdown=True, followlinks=False, onerror=on_walk_error
    ):
        current_path = Path(current)
        retained_dirs = []
        for item in sorted(dirs):
            candidate = current_path / item
            if item in ignored_dirs:
                continue
            try:
                is_symlink = candidate.is_symlink()
            except PermissionError:
                skipped["permission"] += 1
                continue
            if is_symlink:
                skipped["symlink"] += 1
                continue
            retained_dirs.append(item)
        dirs[:] = retained_dirs
        for filename in sorted(filenames):
            path = current_path / filename
            try:
                is_symlink = path.is_symlink()
            except PermissionError:
                skipped["permission"] += 1
                continue
            if is_symlink:
                skipped["symlink"] += 1
                continue
            if path.suffix.lower() not in extensions:
                continue
            try:
                size = path.stat().st_size
            except PermissionError:
                skipped["permission"] += 1
                continue
            except OSError:
                continue
            if size > max_file_bytes:
                skipped["too_large"] += 1
                continue
            if len(selected) >= max_files:
                skipped["file_limit"] += 1
                continue
            if total + size > max_total_bytes:
                skipped["byte_limit"] += 1
                continue
            try:
                text = safe_read_text(path, max_file_bytes)
            except PermissionError:
                skipped["permission"] += 1
                continue
            if text is None:
                skipped["binary"] += 1
                continue
            selected.append((path, text))
            total += size
    selected.sort(key=lambda item: relative_posix(item[0], root))
    return selected, {**skipped, "selected": len(selected), "bytes": total}


def severity_rank(value: str) -> int:
    return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(value.upper(), 0)


def lower_severity(value: str) -> str:
    levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    return levels[max(0, severity_rank(value) - 1)]


def normalize_algorithm(value: str) -> str:
    return value.strip().upper().replace("-", "").replace("_", "").replace(" ", "")


def algorithm_display(value: str) -> str:
    key = normalize_algorithm(value)
    aliases = {
        "RS256": "RSA",
        "RS384": "RSA",
        "RS512": "RSA",
        "PS256": "RSA",
        "PS384": "RSA",
        "PS512": "RSA",
        "ES256": "ECDSA",
        "ES384": "ECDSA",
        "ES512": "ECDSA",
        "EDDSA": "EdDSA",
        "X25519": "X25519",
        "X448": "X448",
        "ECDH": "ECDH",
        "ECDSA": "ECDSA",
        "MLKEM": "ML-KEM",
        "MLDSA": "ML-DSA",
        "SLHDSA": "SLH-DSA",
    }
    return aliases.get(key, value.strip())


def test_only_path(path: str) -> bool:
    parts = {part.lower() for part in Path(path).parts}
    name = Path(path).name.lower()
    return bool(parts & {"test", "tests", "fixtures", "fixture"}) or name.startswith(
        ("test_", "test-", "conftest")
    )
