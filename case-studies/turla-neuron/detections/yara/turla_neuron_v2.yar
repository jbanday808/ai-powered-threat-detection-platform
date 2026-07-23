import "hash"

rule Turla_Neuron_Exact : turla darkneuron
{
    meta:
        author       = "James Banday"
        date_created = "2026-07-22"
        description  = "Exact SHA-256 detection for Turla Neuron"
        sha256       = "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"

    condition:
        hash.sha256(0, filesize) ==
        "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
}

rule Turla_Neuron_Behavior : turla darkneuron
{
    meta:
        author             = "James Banday"
        date_created       = "2026-07-22"
        description        = "Detects Turla Neuron service and command-channel artifacts"
        defender_detection = "Trojan:MSIL/DarkNeuron.B!dha"
        reference          = "https://academy.hackthebox.com/app/module/234/section/2514"
        reference2         = "https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB"
        reference3         = "https://www.ncsc.gov.uk/alerts/turla-group-malware"

    strings:
        $service = "MSExchangeService" ascii wide
        $url     = "https://*:443/ews/exchange/" ascii wide nocase

        $guid1 = "f2949bab-240a-46ca-a455-6f504367ba7d" ascii wide
        $guid2 = "8d963325-01b8-4671-8e82-d0904275ab06" ascii wide

        $c2_key = "cadataKey" ascii wide
        $c2_sig = "cadataSig" ascii wide

        $fn_exec  = "ExecCMD" ascii wide
        $fn_clean = "KillOldThread" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $service and
        $url and
        1 of ($guid*) and
        1 of ($c2_*) and
        1 of ($fn_*)
}
