# Turla Neuron Analysis Scripts

## Overview

These scripts help identify the sample, validate defensive rules, collect evidence from the isolated Windows analysis system, verify cleanup, and check the consistency of the case-study files. None of the scripts should execute or communicate with the malware.

## Safety Notice

> Use these utilities only in an authorized analysis environment. They do not execute the malware.

- Run the Windows evidence collector only after an independently authorized isolated dynamic run has already occurred and before snapshot restoration.
- The cleanup script verifies current state; it does not delete files, stop services, or restore a snapshot.
- No script sends traffic to the malware listener or generates protocol/tasking messages.
- Do not use these scripts on a production system without explicit authorization.
- Keep the analysis VM network adapter disabled.
- Review every output path before using `--force` or `-Force`.

## Script Index

| Script | Platform | Purpose | Executes malware? | Modifies evidence? |
|---|---|---|---|---|
| `collect_static_metadata.sh` | Linux/macOS shell | Verify the expected hash and collect static file metadata | No | No; creates a report |
| `validate_yara_rules.sh` | Linux/macOS shell | Compile YARA and scan supplied files as data | No | No; creates compiled rules/reports |
| `collect_windows_dynamic_evidence.ps1` | Windows PowerShell | Collect service, Registry, HTTP.sys, socket, and Defender state | No | No; creates evidence outputs |
| `verify_windows_cleanup.ps1` | Windows PowerShell | Verify the sample, service, queue association, and active threat are absent | No | No; creates a verification report |
| `inventory_case_evidence.py` | Python 3 | Hash and inventory case-study files | No | No; creates an inventory |
| `validate_case_artifacts.py` | Python 3 | Validate JSON, CSV, links, required files, and sample hash references | No | No; creates a validation report |

Outputs are not overwritten unless the operator explicitly supplies `--force` or `-Force`.

## Recommended Workflow

1. Run `collect_static_metadata.sh` against an analyst-supplied sample path.
2. Run `validate_yara_rules.sh` to compile and scan without execution.
3. After a separately authorized isolated dynamic run, execute `collect_windows_dynamic_evidence.ps1`.
4. After cleanup or snapshot restoration, execute `verify_windows_cleanup.ps1`.
5. Run `inventory_case_evidence.py`.
6. Run `validate_case_artifacts.py`.

This workflow intentionally contains no step that launches, installs, starts, uninstalls, or communicates with the malware.

## Example Commands

### Static metadata

```bash
./collect_static_metadata.sh \
  --sample /authorized/evidence/Microsoft.Exchange.Service.exe \
  --output ../results/static
```

The command refuses a file whose SHA-256 differs from the expected case sample.

### YARA validation

```bash
./validate_yara_rules.sh \
  --rule ../detections/yara/turla_neuron_v2.yar \
  --sample /authorized/evidence/Microsoft.Exchange.Service.exe \
  --output ../results/yara
```

YARA reads the file as data. It does not execute it. The script requires existing `yara` and `yarac` commands and never installs them.

### Windows dynamic-evidence collection

```powershell
.\collect_windows_dynamic_evidence.ps1 `
  -OutputDirectory 'C:\AuthorizedEvidence\TurlaNeuron\Dynamic'
```

To inventory already-created installer artifacts without copying them:

```powershell
.\collect_windows_dynamic_evidence.ps1 `
  -OutputDirectory 'C:\AuthorizedEvidence\TurlaNeuron\Dynamic' `
  -InstallerArtifactDirectory 'C:\AuthorizedEvidence\TurlaNeuron\InstallerArtifacts'
```

This collector reads current state only. It must not be used as a substitute for authorization or isolation controls.

### Cleanup verification

```powershell
.\verify_windows_cleanup.ps1 `
  -SamplePath 'C:\AuthorizedAnalysis\Microsoft.Exchange.Service.exe' `
  -OutputDirectory 'C:\AuthorizedEvidence\TurlaNeuron\Cleanup'
```

The script returns nonzero if the supplied file, service, service Registry key, HTTP.sys service association, or active Defender classification remains.

### Evidence inventory

```bash
python3 inventory_case_evidence.py \
  --case-root .. \
  --output ../results/static/turla_neuron_case_evidence_inventory.csv
```

### Cross-format validation

```bash
python3 validate_case_artifacts.py \
  --case-root .. \
  --output ../results/static/turla_neuron_case_artifacts_validation.txt
```

Use `--force` or `-Force` only when intentionally replacing an earlier generated output. Raw evidence should be versioned or moved to a protected evidence location instead of overwritten.

## Output Locations

- `results/static/`: static metadata, inventories, and cross-format validation
- `results/yara/`: compiled YARA and scan results
- `results/dynamic/`: consolidated Windows runtime evidence
- `results/network/`: HTTP.sys, socket, and network-analysis evidence
- `results/procmon/`: Procmon evidence-handling documentation
- `results/noriben/`: processed Noriben evidence

The PowerShell examples use an external authorized evidence directory by default. If their outputs are later added to the repository, preserve original timestamps and document provenance.

## Collection Versus Interpretation

The collectors record current state and file properties. They do not decide that every service, Registry value, port, or Defender record is malicious. Interpretation belongs in the corresponding analysis packages and should correlate multiple evidence sources.

## Evidence Limitations

- Static metadata identifies a file but does not prove runtime behavior.
- YARA matches scan file content and do not execute the sample.
- Windows evidence collection records current state only.
- An absent service after snapshot restoration does not erase historical analysis evidence.
- The retained malware-run PML was unusable.
- No packet capture, external C2 IP, or external C2 domain was identified.
- HTTP.sys and socket output can change quickly; capture it before cleanup.
- Defender history can remain after successful remediation.

## Requirements

- Bash scripts: Bash, coreutils, `file`; YARA utilities only for YARA validation
- PowerShell scripts: Windows PowerShell with standard Windows networking, CIM, Registry, and Defender cmdlets
- Python scripts: Python 3 standard library only
- Internet access: not required

## Case Details

- Incident: `MAL-2026-0721-NEURON`
- Family: Turla Neuron / DarkNeuron
- Expected SHA-256: `d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29`
- Author: James Banday
- Date: 2026-07-22
