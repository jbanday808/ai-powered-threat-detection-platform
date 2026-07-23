#!/usr/bin/env bash
# Purpose: Collect hashes and basic static metadata without executing the sample.
# Safety: Reads the supplied file only; never launches it or changes source evidence.
# Inputs: --sample FILE --output DIRECTORY [--expected-sha256 HASH] [--force]
# Outputs: turla_neuron_static_metadata.txt in the selected output directory.
# Author: James Banday
# Date: 2026-07-22

set -euo pipefail

EXPECTED_SHA256="d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
sample=""
output=""
force=0

usage() {
    echo "Usage: $0 --sample FILE --output DIRECTORY [--expected-sha256 HASH] [--force]" >&2
}

while (($#)); do
    case "$1" in
        --sample) [[ $# -ge 2 ]] || { usage; exit 2; }; sample=$2; shift 2 ;;
        --output) [[ $# -ge 2 ]] || { usage; exit 2; }; output=$2; shift 2 ;;
        --expected-sha256) [[ $# -ge 2 ]] || { usage; exit 2; }; EXPECTED_SHA256=${2,,}; shift 2 ;;
        --force) force=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: Unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

[[ -n "$sample" && -n "$output" ]] || { echo "ERROR: --sample and --output are required." >&2; usage; exit 2; }
[[ -f "$sample" ]] || { echo "ERROR: Sample is not a regular file: $sample" >&2; exit 1; }
[[ ! -L "$sample" ]] || { echo "ERROR: Refusing a symbolic-link sample path: $sample" >&2; exit 1; }
[[ "$EXPECTED_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "ERROR: Expected SHA-256 must be 64 hexadecimal characters." >&2; exit 2; }

for tool in sha256sum sha1sum md5sum stat file; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: Required tool is unavailable: $tool" >&2; exit 1; }
done

mkdir -p -- "$output"
destination="$output/turla_neuron_static_metadata.txt"
if [[ -e "$destination" && $force -ne 1 ]]; then
    echo "ERROR: Output exists; use --force to replace it: $destination" >&2
    exit 1
fi

actual_sha256=$(sha256sum -- "$sample" | awk '{print tolower($1)}')
if [[ "$actual_sha256" != "$EXPECTED_SHA256" ]]; then
    echo "ERROR: SHA-256 mismatch. Expected $EXPECTED_SHA256 but found $actual_sha256." >&2
    exit 1
fi

tmp=$(mktemp "${destination}.tmp.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
{
    echo "Turla Neuron static metadata"
    echo "Collection date (UTC): $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    echo "Sample basename: $(basename -- "$sample")"
    echo "Sample path supplied by analyst: $sample"
    echo "Size bytes: $(stat -c '%s' -- "$sample")"
    echo "File type: $(file -b -- "$sample")"
    echo "MD5: $(md5sum -- "$sample" | awk '{print $1}')"
    echo "SHA-1: $(sha1sum -- "$sample" | awk '{print $1}')"
    echo "SHA-256: $actual_sha256"
    echo "Expected SHA-256 match: true"
    echo "Safety: File was read for metadata only and was not executed."
} >"$tmp"
mv -f -- "$tmp" "$destination"
trap - EXIT
echo "Created: $destination"
