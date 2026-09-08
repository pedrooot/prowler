#!/usr/bin/env python3
"""Regenerate testdata/mutelist_parity.json from the Python Mutelist.

Run from the repository root:

    python3 prowler-go/scripts/mutelist_golden.py

The cases live in the JSON file itself; this script only recomputes the
`expected` field by running the Python implementation, so the Go port has an
authoritative reference to be tested against.
"""

import enum
import importlib.util
import json
import pathlib
import sys
import types

import yaml

GOLDEN = pathlib.Path("prowler-go/testdata/mutelist_parity.json")
MUTELIST = pathlib.Path("prowler/lib/mutelist/mutelist.py")


def stub_prowler_package() -> None:
    """Load mutelist.py without pulling in the whole SDK."""
    for name in (
        "prowler",
        "prowler.lib",
        "prowler.lib.logger",
        "prowler.lib.outputs",
        "prowler.lib.outputs.common",
        "prowler.lib.outputs.utils",
    ):
        sys.modules.setdefault(name, types.ModuleType(name))

    silent = {m: staticmethod(lambda *a, **k: None) for m in ("error", "warning", "info", "critical", "debug")}
    sys.modules["prowler.lib.logger"].logger = type("Logger", (), silent)()

    class Status(str, enum.Enum):
        PASS = "PASS"
        FAIL = "FAIL"
        MANUAL = "MANUAL"
        MUTED = "MUTED"

    sys.modules["prowler.lib.outputs.common"].Status = Status
    sys.modules["prowler.lib.outputs.utils"].unroll_dict = unroll_dict
    sys.modules["prowler.lib.outputs.utils"].unroll_tags = lambda tags: tags or {}


def unroll_dict(values: dict, separator: str = "=") -> str:
    """Render tags the way the Go implementation does: keys sorted."""
    rendered = ""
    for key, value in sorted(values.items()):
        if isinstance(value, list):
            value = ", ".join(value)
        pair = f"{key}{separator}{value}"
        rendered = pair if not rendered else f"{rendered} | {pair}"
    return rendered


def main() -> None:
    stub_prowler_package()

    spec = importlib.util.spec_from_file_location("mutelist", MUTELIST)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class Concrete(module.Mutelist):
        def is_finding_muted(self, *args, **kwargs):
            return False

    cases = json.loads(GOLDEN.read_text())
    for case in cases:
        mutelist = Concrete(mutelist_content=yaml.safe_load(case["doc"])["Mutelist"])
        case["expected"] = bool(
            mutelist.is_muted(
                case["account"],
                case["check"],
                case["region"],
                case["resource"],
                unroll_dict(case["tags"]),
            )
        )

    GOLDEN.write_text(json.dumps(cases, indent=2) + "\n")
    muted = sum(case["expected"] for case in cases)
    print(f"{GOLDEN}: {muted} muted of {len(cases)} cases")


if __name__ == "__main__":
    main()
