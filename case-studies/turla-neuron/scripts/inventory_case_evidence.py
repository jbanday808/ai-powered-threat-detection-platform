#!/usr/bin/env python3
"""Purpose: Inventory and SHA-256 hash case-study files without changing them.
Safety: Read-only traversal; refuses symlinks and will not overwrite without --force.
Inputs: --case-root DIRECTORY --output FILE [--force].
Outputs: Deterministically ordered UTF-8 CSV inventory.
Author: James Banday
Date: 2026-07-22
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import mimetypes
import os
import sys
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--case-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    case_root = args.case_root.resolve()
    output = args.output.resolve()
    if not case_root.is_dir():
        print(f"ERROR: Case root is not a directory: {case_root}", file=sys.stderr)
        return 2
    if output.exists() and not args.force:
        print(f"ERROR: Output exists; use --force to replace it: {output}", file=sys.stderr)
        return 1
    output.parent.mkdir(parents=True, exist_ok=True)

    rows: list[tuple[str, int, str, str, str]] = []
    for path in sorted(case_root.rglob("*"), key=lambda item: item.as_posix().lower()):
        if path.resolve() == output:
            continue
        if path.is_symlink():
            print(f"ERROR: Refusing to follow symbolic link: {path}", file=sys.stderr)
            return 1
        if not path.is_file():
            continue
        relative = path.relative_to(case_root).as_posix()
        stat = path.stat()
        media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        rows.append(
            (
                relative,
                stat.st_size,
                f"{stat.st_mtime_ns / 1_000_000_000:.9f}",
                sha256_file(path),
                media_type,
            )
        )

    temporary = output.with_name(f".{output.name}.tmp.{os.getpid()}")
    try:
        with temporary.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle, lineterminator="\n")
            writer.writerow(("relative_path", "size_bytes", "mtime_epoch", "sha256", "media_type"))
            writer.writerows(rows)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)

    print(f"Created {output} with {len(rows)} file records.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
