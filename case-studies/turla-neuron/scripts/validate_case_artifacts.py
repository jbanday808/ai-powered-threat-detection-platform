#!/usr/bin/env python3
"""Purpose: Validate JSON, CSV, Markdown links, hashes, and package consistency.
Safety: Reads case-study artifacts only; refuses overwrite without --force.
Inputs: --case-root DIRECTORY --output FILE [--force].
Outputs: Plain-text validation report and nonzero exit status on validation failure.
Author: James Banday
Date: 2026-07-22
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote

EXPECTED_SHA256 = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
LINK_PATTERN = re.compile(r"!?\[[^\]]*]\(([^)]+)\)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--case-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def main() -> int:
    args = parse_args()
    root = args.case_root.resolve()
    output = args.output.resolve()
    if not root.is_dir():
        print(f"ERROR: Case root is not a directory: {root}", file=sys.stderr)
        return 2
    if output.exists() and not args.force:
        print(f"ERROR: Output exists; use --force to replace it: {output}", file=sys.stderr)
        return 1
    output.parent.mkdir(parents=True, exist_ok=True)

    failures: list[str] = []
    json_count = csv_count = markdown_count = link_count = 0

    for path in sorted(root.rglob("*")):
        if path.resolve() == output or path.is_symlink() or not path.is_file():
            if path.is_symlink():
                failures.append(f"Symbolic link not validated: {path.relative_to(root)}")
            continue
        suffix = path.suffix.lower()
        if suffix == ".json":
            json_count += 1
            try:
                json.loads(path.read_text(encoding="utf-8-sig"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                failures.append(f"Invalid JSON {path.relative_to(root)}: {error}")
        elif suffix == ".csv":
            csv_count += 1
            try:
                with path.open(encoding="utf-8-sig", newline="") as handle:
                    rows = list(csv.reader(handle))
                if not rows:
                    failures.append(f"Empty CSV: {path.relative_to(root)}")
                elif any(len(row) != len(rows[0]) for row in rows):
                    failures.append(f"Inconsistent CSV columns: {path.relative_to(root)}")
                elif len(rows[1:]) != len({tuple(row) for row in rows[1:]}):
                    failures.append(f"Duplicate CSV data row: {path.relative_to(root)}")
            except (OSError, UnicodeError, csv.Error) as error:
                failures.append(f"Invalid CSV {path.relative_to(root)}: {error}")
        elif suffix == ".md":
            markdown_count += 1
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                failures.append(f"Unreadable Markdown {path.relative_to(root)}: {error}")
                continue
            for target in LINK_PATTERN.findall(text):
                if target.startswith(("http://", "https://", "#", "mailto:")):
                    continue
                link_count += 1
                clean = unquote(target.split("#", 1)[0])
                resolved = (path.parent / clean).resolve()
                if not inside(resolved, root):
                    failures.append(f"Markdown link escapes case root: {path.relative_to(root)} -> {target}")
                elif not resolved.exists():
                    failures.append(f"Broken Markdown link: {path.relative_to(root)} -> {target}")

    required = [
        root / "reports" / "incident-report.md",
        root / "iocs" / "turla_neuron_iocs.md",
        root / "iocs" / "turla_neuron_iocs.csv",
        root / "iocs" / "turla_neuron_iocs.json",
        root / "detections" / "yara" / "turla_neuron_v2.yar",
        root / "detections" / "sigma" / "win_system_turla_neuron_service_install.yml",
    ]
    for path in required:
        if not path.is_file():
            failures.append(f"Required artifact missing: {path.relative_to(root)}")

    for path in required[:4]:
        if path.is_file() and EXPECTED_SHA256 not in path.read_text(encoding="utf-8-sig", errors="replace"):
            failures.append(f"Expected SHA-256 missing: {path.relative_to(root)}")

    executable_results = [
        path.relative_to(root).as_posix()
        for path in (root / "results").rglob("*.exe")
        if path.is_file()
    ]
    if executable_results:
        failures.append(f"Executable found under results/: {', '.join(executable_results)}")

    lines = [
        "Turla Neuron case-artifact validation",
        f"Case root: {root}",
        f"JSON files parsed: {json_count}",
        f"CSV files checked: {csv_count}",
        f"Markdown files checked: {markdown_count}",
        f"Local Markdown links checked: {link_count}",
        f"Failures: {len(failures)}",
    ]
    lines.extend(f"- {failure}" for failure in failures)
    lines.append(f"Final result: {'FAIL' if failures else 'PASS'}")

    temporary = output.with_name(f".{output.name}.tmp.{os.getpid()}")
    try:
        temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)

    print(lines[-1])
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
