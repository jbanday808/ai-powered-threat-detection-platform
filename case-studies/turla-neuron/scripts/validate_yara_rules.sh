#!/usr/bin/env bash
# Purpose: Compile YARA rules and scan a supplied file without executing it.
# Safety: Performs file-content scanning only; never launches the supplied sample.
# Inputs: --rule FILE --sample FILE --output DIRECTORY [--force]
# Outputs: Compiled rule, source/compiled scan reports, and benign negative-test report.
# Author: James Banday
# Date: 2026-07-22

set -euo pipefail

EXPECTED_SHA256="d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
rule=""
sample=""
output=""
force=0

usage() {
    echo "Usage: $0 --rule FILE --sample FILE --output DIRECTORY [--force]" >&2
}

while (($#)); do
    case "$1" in
        --rule) [[ $# -ge 2 ]] || { usage; exit 2; }; rule=$2; shift 2 ;;
        --sample) [[ $# -ge 2 ]] || { usage; exit 2; }; sample=$2; shift 2 ;;
        --output) [[ $# -ge 2 ]] || { usage; exit 2; }; output=$2; shift 2 ;;
        --force) force=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: Unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

[[ -n "$rule" && -n "$sample" && -n "$output" ]] || { echo "ERROR: --rule, --sample, and --output are required." >&2; usage; exit 2; }
[[ -f "$rule" && ! -L "$rule" ]] || { echo "ERROR: Rule is not a regular non-symlink file: $rule" >&2; exit 1; }
[[ -f "$sample" && ! -L "$sample" ]] || { echo "ERROR: Sample is not a regular non-symlink file: $sample" >&2; exit 1; }
for tool in yarac yara sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: Required tool is unavailable; no package was installed: $tool" >&2; exit 1; }
done

actual_sha256=$(sha256sum -- "$sample" | awk '{print tolower($1)}')
[[ "$actual_sha256" == "$EXPECTED_SHA256" ]] || { echo "ERROR: Refusing scan because sample SHA-256 does not match the expected case sample." >&2; exit 1; }

mkdir -p -- "$output"
compiled="$output/turla_neuron_v2.compiled"
source_report="$output/turla_neuron_yara_source_scan.txt"
compiled_report="$output/turla_neuron_yara_compiled_scan.txt"
negative_report="$output/turla_neuron_yara_negative_test.txt"
for path in "$compiled" "$source_report" "$compiled_report" "$negative_report"; do
    [[ ! -e "$path" || $force -eq 1 ]] || { echo "ERROR: Output exists; use --force: $path" >&2; exit 1; }
done

tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT
yarac "$rule" "$tmpdir/turla_neuron_v2.compiled"
yara --print-meta --print-strings "$rule" "$sample" >"$tmpdir/source.txt"
yara --compiled-rules --print-meta --print-strings "$tmpdir/turla_neuron_v2.compiled" "$sample" >"$tmpdir/compiled.txt"
if [[ -f /bin/ls ]]; then
    yara "$rule" /bin/ls >"$tmpdir/negative.txt"
    [[ ! -s "$tmpdir/negative.txt" ]] || { echo "ERROR: Benign negative test unexpectedly matched." >&2; exit 1; }
else
    echo "SKIPPED: /bin/ls is unavailable." >"$tmpdir/negative.txt"
fi
grep -q '^Turla_Neuron_Exact ' "$tmpdir/source.txt" || { echo "ERROR: Exact rule did not match source-rule scan." >&2; exit 1; }
grep -q '^Turla_Neuron_Behavior ' "$tmpdir/source.txt" || { echo "ERROR: Behavior rule did not match source-rule scan." >&2; exit 1; }
grep -q '^Turla_Neuron_Exact ' "$tmpdir/compiled.txt" || { echo "ERROR: Exact rule did not match compiled-rule scan." >&2; exit 1; }
grep -q '^Turla_Neuron_Behavior ' "$tmpdir/compiled.txt" || { echo "ERROR: Behavior rule did not match compiled-rule scan." >&2; exit 1; }

mv -f -- "$tmpdir/turla_neuron_v2.compiled" "$compiled"
mv -f -- "$tmpdir/source.txt" "$source_report"
mv -f -- "$tmpdir/compiled.txt" "$compiled_report"
mv -f -- "$tmpdir/negative.txt" "$negative_report"
echo "YARA validation passed. Outputs created under: $output"
