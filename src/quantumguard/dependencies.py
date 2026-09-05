from __future__ import annotations

import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import Dependency
from .util import safe_read_text

_MANIFEST_NAMES = {
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "CMakeLists.txt",
    "conanfile.txt",
    "vcpkg.json",
}
_IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "vendor", "dist", "build"}
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(?:\[.*?\])?\s*(?:[<>=!~]+\s*([^;\s]+))?")


def discover_dependencies(root: Path, *, max_file_bytes: int = 2 * 1024 * 1024) -> list[Dependency]:
    root = root.resolve()
    found: dict[tuple[str, str, str], Dependency] = {}
    for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(
            name
            for name in dirs
            if name not in _IGNORED_DIRS and not (current_path / name).is_symlink()
        )
        for name in sorted(set(names) & _MANIFEST_NAMES):
            path = current_path / name
            text = safe_read_text(path, max_file_bytes)
            if text is None:
                continue
            rel = path.relative_to(root).as_posix()
            for item in _parse_manifest(name, text, rel):
                key = (item.ecosystem, item.name.lower(), item.manifest)
                found[key] = item
    return sorted(
        found.values(), key=lambda item: (item.ecosystem, item.name.lower(), item.manifest)
    )


def _parse_manifest(name: str, text: str, rel: str) -> list[Dependency]:
    if name == "requirements.txt":
        return _requirements(text, rel)
    if name == "pyproject.toml":
        return _pyproject(text, rel)
    if name in {"poetry.lock", "uv.lock"}:
        return _toml_lock(text, rel)
    if name in {"package.json", "package-lock.json"}:
        return _package_json(text, rel)
    if name in {"pnpm-lock.yaml", "yarn.lock"}:
        return _js_lock(text, rel)
    if name == "go.mod":
        return _go_mod(text, rel)
    if name == "Cargo.toml":
        return _cargo_toml(text, rel)
    if name == "Cargo.lock":
        return _cargo_lock(text, rel)
    if name == "pom.xml":
        return _pom(text, rel)
    if name in {"build.gradle", "build.gradle.kts"}:
        return _gradle(text, rel)
    if name == "vcpkg.json":
        return _vcpkg(text, rel)
    if name in {"CMakeLists.txt", "conanfile.txt"}:
        return _cpp_text(text, rel)
    return []


def _requirements(text: str, rel: str) -> list[Dependency]:
    result = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(("#", "-", "http:", "https:")):
            continue
        match = _REQ_NAME.match(line)
        if match:
            result.append(Dependency(match.group(1), match.group(2), rel, "pypi"))
    return result


def _pyproject(text: str, rel: str) -> list[Dependency]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    project = data.get("project") or {}
    values: list[str] = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        values.extend(group or [])
    result = _requirements("\n".join(str(value) for value in values), rel)

    poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    for name, value in poetry.items():
        if name.lower() == "python":
            continue
        version: str | None
        if isinstance(value, str):
            version = value
        elif isinstance(value, dict):
            raw_version = value.get("version")
            version = raw_version if isinstance(raw_version, str) else None
        else:
            version = None
        result.append(Dependency(name, str(version) if version is not None else None, rel, "pypi"))
    return result


def _toml_lock(text: str, rel: str) -> list[Dependency]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    return [
        Dependency(str(item["name"]), str(item.get("version") or "") or None, rel, "pypi", False)
        for item in data.get("package", [])
        if isinstance(item, dict) and item.get("name")
    ]


def _package_json(text: str, rel: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    result = []
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        for dep_name, version in (data.get(field) or {}).items():
            result.append(Dependency(dep_name, str(version), rel, "npm", field == "dependencies"))
    if rel.endswith("package-lock.json"):
        for dep_name, value in (data.get("packages") or {}).items():
            if not dep_name.startswith("node_modules/"):
                continue
            result.append(
                Dependency(
                    dep_name.removeprefix("node_modules/"),
                    str((value or {}).get("version") or "") or None,
                    rel,
                    "npm",
                    False,
                )
            )
    return result


def _js_lock(text: str, rel: str) -> list[Dependency]:
    result = []
    for line in text.splitlines():
        stripped = line.strip().strip('"').strip("'")
        if not stripped or stripped.startswith(("#", "lockfileVersion", "version:")):
            continue
        match = re.match(r"/?(@?[^:@\s/]+(?:/[^:@\s]+)?)[@:].*?(\d+\.\d+[^\s:]*)?", stripped)
        if match:
            result.append(Dependency(match.group(1), match.group(2), rel, "npm", False))
    return result


def _go_mod(text: str, rel: str) -> list[Dependency]:
    result = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "require (":
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if stripped.startswith("require "):
            stripped = stripped.removeprefix("require ").strip()
        elif not in_block:
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            result.append(Dependency(parts[0], parts[1], rel, "go"))
    return result


def _cargo_toml(text: str, rel: str) -> list[Dependency]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    result = []
    for field in ("dependencies", "dev-dependencies", "build-dependencies"):
        for dep_name, value in (data.get(field) or {}).items():
            version = value if isinstance(value, str) else (value or {}).get("version")
            result.append(
                Dependency(
                    dep_name,
                    str(version) if version else None,
                    rel,
                    "cargo",
                    field == "dependencies",
                )
            )
    return result


def _cargo_lock(text: str, rel: str) -> list[Dependency]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    return [
        Dependency(str(item["name"]), str(item.get("version") or "") or None, rel, "cargo", False)
        for item in data.get("package", [])
        if isinstance(item, dict) and item.get("name")
    ]


def _pom(text: str, rel: str) -> list[Dependency]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    result = []
    for dep in root.findall(".//{*}dependency"):
        group = dep.findtext("{*}groupId") or ""
        artifact = dep.findtext("{*}artifactId") or ""
        version = dep.findtext("{*}version")
        if artifact:
            result.append(Dependency(f"{group}:{artifact}".strip(":"), version, rel, "maven"))
    return result


def _gradle(text: str, rel: str) -> list[Dependency]:
    pattern = re.compile(
        r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*[\(\s]['"]([^:'"]+):([^:'"]+)(?::([^'"]+))?"""
    )
    return [
        Dependency(f"{m.group(1)}:{m.group(2)}", m.group(3), rel, "maven")
        for m in pattern.finditer(text)
    ]


def _vcpkg(text: str, rel: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    result = []
    for value in data.get("dependencies", []):
        if isinstance(value, str):
            result.append(Dependency(value, None, rel, "vcpkg"))
        elif isinstance(value, dict) and value.get("name"):
            result.append(
                Dependency(
                    str(value["name"]), str(value.get("version>=") or "") or None, rel, "vcpkg"
                )
            )
    return result


def _cpp_text(text: str, rel: str) -> list[Dependency]:
    if rel.endswith("conanfile.txt"):
        result = []
        in_requires = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                in_requires = stripped.lower() == "[requires]"
                continue
            if not in_requires or not stripped or stripped.startswith(("#", ";")):
                continue
            name = stripped.split("/", 1)[0].strip()
            if name:
                result.append(Dependency(name, None, rel, "cpp"))
        return result

    result = []
    for line in text.splitlines():
        match = re.search(r"find_package\s*\(?\s*([A-Za-z0-9_.+-]+)", line, re.I)
        if match:
            result.append(Dependency(match.group(1), None, rel, "cpp"))
    return result


def crypto_dependency(name: str) -> bool:
    lowered = name.lower()
    signals = {
        "cryptography",
        "pycryptodome",
        "pycryptodomex",
        "pyjwt",
        "openssl",
        "libressl",
        "boringssl",
        "rustls",
        "ring",
        "webcrypto",
        "node-forge",
        "jsonwebtoken",
        "bouncycastle",
        "tink",
        "oqs",
        "liboqs",
    }
    return any(signal in lowered for signal in signals)
