/*
    Rule: GootLoader_Combined_Static_IOC
    Purpose: Detect the GootLoader JavaScript sample analyzed in this case study.

    This rule uses only confirmed static analysis findings:
    - JavaScript and jQuery strings observed in the sample
    - Suspicious injected functions
    - Obfuscated variable names
    - Runtime reconstruction-related indicators

    No network indicators, domains, IP addresses, payload names, persistence
    artifacts, or unobserved behaviors are included.
*/

rule GootLoader_Combined_Static_IOC
{
    meta:
        author = "James Banday"
        malware_family = "GootLoader"
        version = "1.0"
        date = "2026-07-05"
        description = "Detects GootLoader-style obfuscated JavaScript using static code indicators identified during malware analysis."
        reference = "Static Analysis, VirusTotal, MalwareBazaar"
        sha256 = "53f8a46c948c968fe753a5f723bdf99d3b3d141dc3dec3d8e36480975c7ce879"

    strings:
        /*
            JavaScript and jQuery indicators observed in the analyzed script.
            These strings help identify the script context without relying on
            network or runtime-only artifacts.
        */
        $s1  = "window.document" ascii
        $s2  = "jQuery.acceptData" ascii
        $s3  = "jQuery.expr.match.needsContext" ascii

        /*
            Suspicious functions identified during static review.
            These indicators are tied to the injected and reconstruction-related
            logic observed in the GootLoader JavaScript sample.
        */
        $s4  = "function stop" ascii
        $s5  = "function returned" ascii
        $s6  = "function adjusted" ascii
        $s7  = "function fxNow" ascii
        $s8  = "function el" ascii

        /*
            Obfuscated or suspicious variable names observed during analysis.
        */
        $s9  = "hooks" ascii
        $s10 = "whitespace" ascii
        $s11 = "isSuccess" ascii
        $s12 = "preferredDoc" ascii
        $s13 = "preservedScriptAttributes" ascii

        /*
            Runtime reconstruction and script behavior indicators observed in
            the static JavaScript review.
        */
        $s14 = "createCache()" ascii
        $s15 = "pixelPositionVal" ascii
        $s16 = "rbracket" ascii
        $s17 = "callbackName" ascii

    condition:
        filesize < 500KB and
        8 of ($s*)
}
