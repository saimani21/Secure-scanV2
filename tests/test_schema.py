from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


def test_repository_schemas_are_valid():
    root = Path(__file__).parents[1] / "schemas"
    for schema_path in root.glob("*.schema.json"):
        Draft202012Validator.check_schema(json.loads(schema_path.read_text(encoding="utf-8")))
