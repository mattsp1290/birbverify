import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from birbverify.contract import Manifest, Request

ROOT = Path(__file__).resolve().parents[1] / "contracts/v1"


def test_published_schemas_match_models():
    for model in (Request, Manifest):
        assert json.loads((ROOT / f"{model.__name__.lower()}.schema.json").read_text()) == (
            model.model_json_schema()
        )


def test_consumer_examples():
    request = Request.model_validate_json((ROOT / "request.example.json").read_text())
    assert Request.model_validate_json(request.model_dump_json()) == request
    with pytest.raises(ValidationError):
        request.request_id = "different"
    rejected = list(ROOT.glob("reject-*.json"))
    assert len(rejected) == 3
    for path in rejected:
        with pytest.raises(ValidationError):
            Request.model_validate_json(path.read_text())


def test_canonical_payload_golden_hash():
    from birbverify.contract import digest

    request = Request.model_validate_json((ROOT / "request.example.json").read_text())
    assert digest(request) == (ROOT / "canonical.example.sha256").read_text().strip()


def test_manifest_compatibility_and_consistency():
    manifest = Manifest.model_validate_json((ROOT / "manifest.example.json").read_text())
    assert Manifest.model_validate_json(manifest.model_dump_json()) == manifest
    for update in (
        {"termination": "unknown"},
        {"cancellation": "acknowledged"},
        {"finished_at": "2000-01-01T00:00:00Z"},
        {"checks": [record.model_dump(mode="json") for record in manifest.checks] * 2},
    ):
        with pytest.raises(ValidationError):
            Manifest.model_validate({**manifest.model_dump(mode="json"), **update})
