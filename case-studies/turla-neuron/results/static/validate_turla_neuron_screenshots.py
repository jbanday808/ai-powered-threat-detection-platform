#!/usr/bin/env python3
"""Validate Turla Neuron report screenshot coverage using only the standard library."""

from collections import Counter
from pathlib import Path
import re
import sys


CASE_DIR = Path(__file__).resolve().parents[2]
REPORT = CASE_DIR / "reports" / "incident-report.md"
INVENTORY = CASE_DIR / "results" / "static" / "turla_neuron_screenshot_inventory.txt"
OUTPUT = CASE_DIR / "results" / "static" / "turla_neuron_screenshot_validation.txt"

REQUIRED_FINAL = [
    "TurlaNeuron_22_Dynamic_ZoneMap_Registry_Modifications.png",
    "TurlaNeuron_23_Noriben_Filtered_Timeline_Activity.png",
    "TurlaNeuron_24_Dynamic_HostSpecific_SYSTEM_Storage_Directory.png",
    "TurlaNeuron_25_Dynamic_HTTPsys_EWS_Exchange_URL_Registration.png",
    "TurlaNeuron_26_Dynamic_Installer_Log_Service_Success.png",
    "TurlaNeuron_27_Dynamic_MSExchangeService_EventLog_Source.png",
    "TurlaNeuron_28_Dynamic_Service_Registry_Persistence.png",
    "TurlaNeuron_29_Defender_DarkNeuron_Quarantined_RecycleBin.png",
    "TurlaNeuron_30_Defender_DarkNeuron_Detection_and_Remediation_History.png",
    "TurlaNeuron_31_Defender_DarkNeuron_Inactive_Cleanup_Verification.png",
    "TurlaNeuron_32_Defender_Final_Scan_Threat_Inactive.png",
]

IMAGE_RE = re.compile(r"!\[[^\]]*\]\(([^)]+)\)")
ANNEX_FILE_RE = re.compile(r"`([^`]+\.(?:png|jpg|jpeg|webp))`", re.IGNORECASE)


def show(items: list[str]) -> str:
    return ", ".join(items) if items else "None"


def main() -> int:
    report_text = REPORT.read_text(encoding="utf-8")
    inventory = [
        line for line in INVENTORY.read_text(encoding="utf-8").splitlines() if line
    ]

    body, separator, annex_tail = report_text.partition(
        "## Annex C — Evidence and Screenshot Index"
    )
    if not separator:
        raise ValueError("Annex C heading is missing")
    annex = annex_tail.partition("## References")[0]

    body_refs = IMAGE_RE.findall(body)
    resolved = [(REPORT.parent / reference).resolve() for reference in body_refs]
    embedded_names = [path.name for path in resolved]
    annex_names = ANNEX_FILE_RE.findall(annex)

    broken_paths = [
        body_refs[index] for index, path in enumerate(resolved) if not path.is_file()
    ]
    outside_paths = [
        body_refs[index]
        for index, path in enumerate(resolved)
        if CASE_DIR not in path.parents
    ]
    missing_from_body = sorted(set(inventory) - set(embedded_names))
    incorrect_names = sorted(set(embedded_names) - set(inventory))
    absent_from_annex = sorted(set(inventory) - set(annex_names))
    unexpected_annex = sorted(set(annex_names) - set(inventory))
    repeated_refs = sorted(
        f"{name} ({count} references)"
        for name, count in Counter(embedded_names).items()
        if count > 1
    )
    duplicate_annex = sorted(
        name for name, count in Counter(annex_names).items() if count > 1
    )

    required_missing_body = [
        name for name in REQUIRED_FINAL if embedded_names.count(name) != 1
    ]
    required_missing_annex = [
        name for name in REQUIRED_FINAL if annex_names.count(name) != 1
    ]
    required_broken = [
        reference
        for index, reference in enumerate(body_refs)
        if resolved[index].name in REQUIRED_FINAL and not resolved[index].is_file()
    ]
    required_incorrect_paths = [
        reference
        for index, reference in enumerate(body_refs)
        if resolved[index].name in REQUIRED_FINAL
        and reference != f"../screenshots/{resolved[index].name}"
    ]

    failures = (
        broken_paths
        or outside_paths
        or missing_from_body
        or incorrect_names
        or absent_from_annex
        or unexpected_annex
        or repeated_refs
        or duplicate_annex
        or required_missing_body
        or required_missing_annex
        or required_broken
        or required_incorrect_paths
        or len(set(embedded_names)) != len(inventory)
    )
    result = "FAIL" if failures else "PASS"

    lines = [
        "Turla Neuron Screenshot Validation",
        "==================================",
        "",
        f"Report: {REPORT.relative_to(CASE_DIR.parent.parent)}",
        f"Inventory: {INVENTORY.relative_to(CASE_DIR.parent.parent)}",
        "",
        f"Total screenshots found: {len(inventory)}",
        f"Total unique screenshots embedded: {len(set(embedded_names))}",
        f"Total image references in the report: {len(body_refs)}",
        f"Screenshots missing from the report: {show(missing_from_body)}",
        f"Broken image paths: {show(broken_paths)}",
        f"Image paths outside case-study directory: {show(outside_paths)}",
        f"Incorrect or uninventoried image filenames: {show(incorrect_names)}",
        f"Total Annex C entries: {len(annex_names)}",
        f"Screenshots absent from Annex C: {show(absent_from_annex)}",
        f"Unexpected Annex C entries: {show(unexpected_annex)}",
        f"Repeated references: {show(repeated_refs)}",
        f"Duplicate Annex C entries: {show(duplicate_annex)}",
        "",
        "Required screenshots 22-32:",
        f"- Referenced exactly once in main report body: {'PASS' if not required_missing_body else 'FAIL'}",
        f"- Listed exactly once in Annex C: {'PASS' if not required_missing_annex else 'FAIL'}",
        f"- Relative paths exist: {'PASS' if not required_broken else 'FAIL'}",
        f"- Exact ../screenshots/ filenames used: {'PASS' if not required_incorrect_paths else 'FAIL'}",
        f"- Missing or repeated in body: {show(required_missing_body)}",
        f"- Missing or repeated in Annex C: {show(required_missing_annex)}",
        f"- Broken required paths: {show(required_broken)}",
        f"- Incorrect required paths: {show(required_incorrect_paths)}",
        "",
        "Duplicate or alternate screenshots identified:",
        "- TurlaNeuron_04_Refined_YARA_v2_Rule_Source_Code.png is a possible alternate capture of TurlaNeuron_03_Refined_YARA_v2_Rule_Source_Code.png.",
        "",
        f"Final result: {result}",
        "",
    ]
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines), end="")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
