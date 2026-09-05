from __future__ import annotations

from pathlib import Path

import quantumguard.dependencies as deps


def _names(items):
    return {(item.ecosystem, item.name, item.version, item.direct) for item in items}


def test_python_manifest_parsers_cover_pep621_poetry_and_locks() -> None:
    requirements = deps._parse_manifest(
        "requirements.txt",
        "# comment\n-r base.txt\nhttps://host.invalid/pkg.whl\ncryptography[ssh]==45.0.6\nrequests>=2\n",
        "requirements.txt",
    )
    assert _names(requirements) == {
        ("pypi", "cryptography", "45.0.6", True),
        ("pypi", "requests", "2", True),
    }

    pyproject = deps._parse_manifest(
        "pyproject.toml",
        """
[project]
dependencies = ["cryptography>=45", "requests"]
[project.optional-dependencies]
test = ["pytest==9.1.1"]
[tool.poetry.dependencies]
python = "^3.11"
PyJWT = "^2.10"
pycryptodome = {version = "^3.20"}
""",
        "pyproject.toml",
    )
    observed = {(item.name.lower(), item.version) for item in pyproject}
    assert observed == {
        ("cryptography", "45"),
        ("requests", None),
        ("pytest", "9.1.1"),
        ("pyjwt", "^2.10"),
        ("pycryptodome", "^3.20"),
    }
    assert deps._parse_manifest("pyproject.toml", "[broken", "pyproject.toml") == []

    lock = deps._parse_manifest(
        "uv.lock",
        '[[package]]\nname = "cryptography"\nversion = "45.0.6"\n[[package]]\nname = "requests"\n',
        "uv.lock",
    )
    assert _names(lock) == {
        ("pypi", "cryptography", "45.0.6", False),
        ("pypi", "requests", None, False),
    }
    assert deps._parse_manifest("poetry.lock", "[broken", "poetry.lock") == []


def test_javascript_go_and_rust_manifest_parsers() -> None:
    package = deps._parse_manifest(
        "package.json",
        '{"dependencies":{"jsonwebtoken":"9.0.2"},'
        '"devDependencies":{"eslint":"9"},'
        '"optionalDependencies":{"node-forge":"1.3.1"}}',
        "package.json",
    )
    assert _names(package) == {
        ("npm", "jsonwebtoken", "9.0.2", True),
        ("npm", "eslint", "9", False),
        ("npm", "node-forge", "1.3.1", False),
    }

    package_lock = deps._parse_manifest(
        "package-lock.json",
        '{"packages":{"":{"name":"root"},'
        '"node_modules/jsonwebtoken":{"version":"9.0.2"},'
        '"node_modules/@scope/crypto":{"version":"1.2.3"}}}',
        "package-lock.json",
    )
    assert _names(package_lock) == {
        ("npm", "jsonwebtoken", "9.0.2", False),
        ("npm", "@scope/crypto", "1.2.3", False),
    }
    assert deps._parse_manifest("package.json", "{broken", "package.json") == []

    js_lock = deps._parse_manifest(
        "yarn.lock",
        'jsonwebtoken@^9.0.0:\n  version: "9.0.2"\n@scope/crypto@^1.0.0:\n',
        "yarn.lock",
    )
    assert {item.name for item in js_lock} >= {"jsonwebtoken", "@scope/crypto"}

    go = deps._parse_manifest(
        "go.mod",
        "module example\nrequire golang.org/x/crypto v0.40.0\nrequire (\n"
        "github.com/cloudflare/circl v1.6.1\n)\n",
        "go.mod",
    )
    assert {(item.name, item.version) for item in go} == {
        ("golang.org/x/crypto", "v0.40.0"),
        ("github.com/cloudflare/circl", "v1.6.1"),
    }

    cargo = deps._parse_manifest(
        "Cargo.toml",
        """
[dependencies]
ring = "0.17"
rustls = { version = "0.23" }
[dev-dependencies]
criterion = "0.5"
[build-dependencies]
cc = "1"
""",
        "Cargo.toml",
    )
    assert _names(cargo) == {
        ("cargo", "ring", "0.17", True),
        ("cargo", "rustls", "0.23", True),
        ("cargo", "criterion", "0.5", False),
        ("cargo", "cc", "1", False),
    }
    assert deps._parse_manifest("Cargo.toml", "[broken", "Cargo.toml") == []

    cargo_lock = deps._parse_manifest(
        "Cargo.lock",
        '[[package]]\nname = "ring"\nversion = "0.17.14"\n'
        '[[package]]\nname = "rustls"\nversion = "0.23.31"\n',
        "Cargo.lock",
    )
    assert all(item.direct is False for item in cargo_lock)
    assert deps._parse_manifest("Cargo.lock", "[broken", "Cargo.lock") == []


def test_jvm_and_cpp_manifest_parsers() -> None:
    pom = deps._parse_manifest(
        "pom.xml",
        """<project xmlns="urn:test"><dependencies><dependency>
<groupId>org.bouncycastle</groupId><artifactId>bcprov</artifactId><version>1.81</version>
</dependency></dependencies></project>""",
        "pom.xml",
    )
    assert _names(pom) == {("maven", "org.bouncycastle:bcprov", "1.81", True)}
    assert deps._parse_manifest("pom.xml", "<broken", "pom.xml") == []

    gradle = deps._parse_manifest(
        "build.gradle",
        'implementation "org.bouncycastle:bcprov:1.81"\n'
        'testImplementation("com.example:test-support:2")\n',
        "build.gradle",
    )
    assert {(item.name, item.version) for item in gradle} == {
        ("org.bouncycastle:bcprov", "1.81"),
        ("com.example:test-support", "2"),
    }

    vcpkg = deps._parse_manifest(
        "vcpkg.json",
        '{"dependencies":["openssl",{"name":"liboqs","version>=":"0.12.0"}]}',
        "vcpkg.json",
    )
    assert _names(vcpkg) == {
        ("vcpkg", "openssl", None, True),
        ("vcpkg", "liboqs", "0.12.0", True),
    }
    assert deps._parse_manifest("vcpkg.json", "{broken", "vcpkg.json") == []

    cmake = deps._parse_manifest(
        "CMakeLists.txt",
        "find_package(OpenSSL REQUIRED)\nfind_package(liboqs)\n",
        "CMakeLists.txt",
    )
    conan = deps._parse_manifest(
        "conanfile.txt",
        "[requires]\nopenssl/3.5.0\nliboqs/0.12.0\n",
        "conanfile.txt",
    )
    assert {item.name for item in cmake} == {"OpenSSL", "liboqs"}
    assert {item.name for item in conan} == {"openssl", "liboqs"}
    assert deps._parse_manifest("unknown.lock", "anything", "unknown.lock") == []


def test_dependency_discovery_is_bounded_sorted_and_ignores_build_trees(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2\ncryptography==45\n", encoding="utf-8")
    nested = tmp_path / "service"
    nested.mkdir()
    (nested / "package.json").write_text(
        '{"dependencies":{"jsonwebtoken":"9.0.2"}}', encoding="utf-8"
    )
    ignored = tmp_path / "node_modules"
    ignored.mkdir()
    (ignored / "package.json").write_text(
        '{"dependencies":{"node-forge":"1.3.1"}}', encoding="utf-8"
    )
    oversized = tmp_path / "vendor" / "requirements.txt"
    oversized.parent.mkdir()
    oversized.write_text("pycryptodome==3.20\n", encoding="utf-8")

    found = deps.discover_dependencies(tmp_path, max_file_bytes=4096)
    assert [(item.ecosystem, item.name.lower()) for item in found] == sorted(
        [(item.ecosystem, item.name.lower()) for item in found]
    )
    assert {item.name.lower() for item in found} == {
        "cryptography",
        "jsonwebtoken",
        "requests",
    }


def test_crypto_dependency_signals_are_specific() -> None:
    for name in ("cryptography", "PyJWT", "@scope/node-forge", "liboqs", "rustls"):
        assert deps.crypto_dependency(name)
    for name in ("requests", "numpy", "crypto-wallet-ui"):
        assert not deps.crypto_dependency(name)
