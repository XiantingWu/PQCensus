from __future__ import annotations

from pathlib import Path

from quantumguard import audit
from quantumguard.reporting import cyclonedx_cbom_document, inventory_document


def test_static_dependencies_become_inventory_assets(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "cryptography==45.0.6\nrequests>=2\n", encoding="utf-8"
    )
    result = audit(tmp_path)
    assert {(item.name, item.version) for item in result.dependencies} == {
        ("cryptography", "45.0.6"),
        ("requests", "2"),
    }
    assets = inventory_document(result)["assets"]
    assert any(
        item["asset_type"] == "crypto-library" and item["name"] == "cryptography" for item in assets
    )


def test_cyclonedx_graph_links_dependency_to_crypto_asset(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("PyJWT==2.10.1\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        'import jwt\njwt.encode({"sub": "1"}, "key", algorithm="RS256")\n',
        encoding="utf-8",
    )
    document = cyclonedx_cbom_document(audit(tmp_path))
    pyjwt_ref = next(
        item["bom-ref"]
        for item in document["components"]
        if item["type"] == "library" and item["name"] == "PyJWT"
    )
    rsa_ref = next(
        item["bom-ref"]
        for item in document["components"]
        if item["type"] == "cryptographic-asset" and item["name"].startswith("RSA ")
    )
    relationship = next(item for item in document["dependencies"] if item["ref"] == pyjwt_ref)
    assert rsa_ref in relationship["dependsOn"]
