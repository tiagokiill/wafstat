"""Validate public WAFstat JSON examples against the published schema."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "docs" / "public_scanner_output_schema.json"
EXAMPLE_PATHS = [ROOT / "examples" / "wafstat_dry_run_example.json"]


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for path in EXAMPLE_PATHS:
        instance = json.loads(path.read_text(encoding="utf-8"))
        errors = sorted(validator.iter_errors(instance), key=lambda item: list(item.path))
        if errors:
            for error in errors:
                location = "/".join(str(part) for part in error.absolute_path) or "<root>"
                print(f"{path}: {location}: {error.message}")
            return 1
        print(f"VALID {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
