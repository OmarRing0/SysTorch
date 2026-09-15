/*
    for real triage work, replace/extend this folder
    with a maintained signature set (e.g. a YARA port of the classic
    PEiD userdb, or your own team's rules). SysTorch will compile every
    .yar/.yara file found in the folder you point it at.

    Structural identification signatures only -- no exploit or malicious
    code of any kind.
*/

rule UPX_Stub
{
    meta:
        description = "UPX-packed executable (32-bit stub)"
        confidence = "MEDIUM"
    strings:
        $stub = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB }
        $sec0 = "UPX0"
        $sec1 = "UPX1"
    condition:
        $stub or ($sec0 and $sec1)
}

rule VMProtect_Sections
{
    meta:
        description = "VMProtect-protected executable (section-name marker)"
        confidence = "HIGH"
    strings:
        $s1 = ".vmp0" ascii
        $s2 = ".vmp1" ascii
    condition:
        any of them
}

rule Themida_Marker
{
    meta:
        description = "Themida/WinLicense-protected executable"
        confidence = "HIGH"
    strings:
        $sec = ".themida" ascii
        $s1 = "Themida" ascii
        $s2 = "WinLicense" ascii
    condition:
        $sec or any of ($s1, $s2)
}

rule WIBU_CodeMeter
{
    meta:
        description = "WIBU-SYSTEMS CodeMeter / AxProtector licensing+protection layer"
        confidence = "HIGH"
    strings:
        $s1 = "WIBU-SYSTEMS" ascii
        $s2 = "CodeMeter" ascii
        $s3 = "AxProtector" ascii
        $dll1 = "WibuCm32.dll" ascii nocase
        $dll2 = "CmDLL32.dll" ascii nocase
    condition:
        any of them
}
