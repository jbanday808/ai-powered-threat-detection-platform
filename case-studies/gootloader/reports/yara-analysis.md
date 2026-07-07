# YARA Analysis – GootLoader

## Executive Summary

A custom YARA rule was created to detect the GootLoader JavaScript sample using static indicators found during analysis.

The rule focused on obfuscated JavaScript, suspicious injected functions, jQuery-related indicators, and runtime string reconstruction patterns.

The rule successfully matched the original GootLoader JavaScript sample during validation.

---

## What is YARA?

YARA is a tool security analysts use to create detection rules.

These rules look for specific strings, patterns, or characteristics inside suspicious files.

YARA helps analysts detect malware without running the file.

---

## Detection Objective

The goal of the YARA rule was to detect the GootLoader JavaScript sample based on static indicators observed during analysis.

The rule focused on:

* Obfuscated JavaScript
* Suspicious injected functions
* Runtime string reconstruction patterns
* JavaScript and jQuery-related indicators
* Static indicators observed during analysis

---

## Confirmed Static Indicators Used

| Indicator Type | Indicator | Purpose |
| --- | --- | --- |
| JavaScript Object | `window.document` | Browser-style JavaScript reference |
| jQuery Indicator | `jQuery.acceptData` | Legitimate-looking code used in the script |
| jQuery Indicator | `jQuery.expr.match.needsContext` | Legitimate-looking code used in the script |
| Suspicious Function | `function stop` | Injected function observed during static analysis |
| Suspicious Function | `function returned` | String reconstruction-related function |
| Suspicious Function | `function adjusted` | String reconstruction-related function |
| Suspicious Function | `function fxNow` | String reconstruction-related function |
| Suspicious Function | `function el` | String extraction-related function |
| Variable | `hooks` | Obfuscated variable |
| Variable | `whitespace` | Obfuscated variable |
| Variable | `isSuccess` | Obfuscated variable |
| Variable | `preferredDoc` | Document reference variable |
| Variable | `preservedScriptAttributes` | Script-related variable |

---

## Custom YARA Rule

```yara
rule GootLoader_Combined_Static_IOC
{
    meta:
        description = "Detects GootLoader-style obfuscated JavaScript using static code indicators and execution artifacts"
        author = "James Banday"
        date = "2026-07-05"
        malware_family = "GootLoader"
        version = "1.0"
        reference = "Static analysis and VirusTotal sample details"
        sha256 = "53f8a46c948c968fe753a5f723bdf99d3b3d141dc3dec3d8e36480975c7ce879"

    strings:

        // JavaScript / jQuery Indicators
        $s1 = "window.document" ascii
        $s2 = "jQuery.acceptData" ascii
        $s3 = "jQuery.expr.match.needsContext" ascii

        // Suspicious Obfuscated Functions
        $s4 = "function stop" ascii
        $s5 = "function returned" ascii
        $s6 = "function adjusted" ascii
        $s7 = "function fxNow" ascii
        $s8 = "function el" ascii

        // Obfuscated Variable Names
        $s9  = "hooks" ascii
        $s10 = "whitespace" ascii
        $s11 = "isSuccess" ascii
        $s12 = "preferredDoc" ascii
        $s13 = "preservedScriptAttributes" ascii

        // Obfuscation / Runtime Reconstruction Patterns
        $s14 = "createCache()" ascii
        $s15 = "pixelPositionVal" ascii
        $s16 = "rbracket" ascii
        $s17 = "callbackName" ascii

    condition:
        filesize < 500KB and
        8 of ($s*)
}
```

---

## Rule Logic

| Rule Component | Purpose |
| --- | --- |
| `filesize < 500KB` | Limits matching to smaller script-like files. |
| JavaScript and jQuery strings | Identifies script content seen in the sample. |
| Suspicious functions | Detects functions observed during static analysis. |
| Obfuscated variables | Detects variable names found in the reviewed JavaScript. |
| `8 of ($s*)` | Requires multiple indicators before the rule matches. |

### Simple Summary

The rule does not rely on one string. It requires several indicators to appear together before reporting a match.

---

## Validation Result

The custom YARA rule successfully detected the original GootLoader JavaScript sample.

The validation confirmed that the static indicators selected during analysis were useful for identifying the sample.

![YARA Rule Match](../screenshots/GootLoader_13_YARA_Rule_Match.png)

| Validation Item | Result |
| --- | --- |
| Malware Family | GootLoader |
| Sample Name | `Legal_Case_Documents_2026.js` |
| SHA-256 | `53f8a46c948c968fe753a5f723bdf99d3b3d141dc3dec3d8e36480975c7ce879` |
| YARA Rule | `GootLoader_Combined_Static_IOC` |
| Detection Result | Match observed |

---

## Detection Scope

This rule was validated against the analyzed GootLoader JavaScript sample.

It is useful for defensive triage and portfolio demonstration. Additional testing would be needed before enterprise-wide production use.

| Scope Area | Status |
| --- | --- |
| Original sample detection | Confirmed |
| Domain detection | Not applicable |
| IP detection | Not applicable |
| Payload detection | Not observed |
| Persistence detection | Not observed |
| Child process detection | Not observed |

---

## MITRE ATT&CK Relevance

| Tactic | Technique | ID | YARA Relevance |
| --- | --- | --- | --- |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | Detects JavaScript indicators in the sample. |
| Defense Evasion | Obfuscated Files or Information | T1027 | Detects obfuscated strings, functions, and variables. |

---

## Key Findings

* A custom YARA rule was created for the GootLoader JavaScript sample.
* The rule used static indicators found during analysis.
* The rule included JavaScript, jQuery, function, and variable indicators.
* The rule successfully matched the original sample.
* No domains, IP addresses, URLs, payloads, child processes, or persistence were used in the rule.

---

## Analyst Assessment

The YARA rule provides a practical host-based detection method for the analyzed GootLoader JavaScript sample.

The strongest rule logic comes from the combination of obfuscated JavaScript indicators and suspicious functions observed during static analysis.

This rule should be treated as a focused detection for this case study, not as a complete detection for every GootLoader variant.

---

## References

* [YARA Documentation](https://yara.readthedocs.io/)
* [MITRE ATT&CK – Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
* [MITRE ATT&CK – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
* [MalwareBazaar](https://bazaar.abuse.ch/)
* [VirusTotal](https://www.virustotal.com/)
