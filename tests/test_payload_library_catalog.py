from pathlib import Path

import yaml

from avvp.services.payload_library.catalog import PAYLOAD_CATALOG
from avvp.services.payload_library.generator import generate


def test_payload_catalog_includes_expanded_categories():
    expected = {"sql-injection", "xss", "auth", "headers", "open-redirect", "csrf", "lfi", "ssrf", "ssti", "jwt"}
    assert expected.issubset(PAYLOAD_CATALOG.keys())
    for category in expected:
        assert len(PAYLOAD_CATALOG[category]) >= 2


def test_generator_writes_categorized_templates(tmp_path):
    out_dir = generate(n=20, out_dir=str(tmp_path))
    base = Path(out_dir)
    for category in ["csrf", "lfi", "ssrf", "ssti", "jwt"]:
        category_dir = base / category
        assert category_dir.is_dir()
        files = sorted(category_dir.glob("*.yaml"))
        assert files
        obj = yaml.safe_load(files[0].read_text(encoding="utf-8"))
        assert obj["metadata"]["category"] == category
        assert "tags" in obj["info"]
        assert obj["requests"][0]["method"] in {"GET", "POST", "OPTIONS"}
