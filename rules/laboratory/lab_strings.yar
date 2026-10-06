// Laboratory educational rules. They match harmless, deliberately-authored strings used by
// the lab_samples suite. They do not describe real malware families.

rule LAB_Network_Strings
{
    meta:
        rule_id = "LAB-001"
        description = "Binary contains laboratory network marker strings (URL or HTTP verb)"
        author = "MalvaX project"
        references = "docs/static-analysis.md"
        severity = "low"
    strings:
        $url = "http://" ascii
        $get = "GET /" ascii
    condition:
        any of them
}

rule LAB_Shell_Reference
{
    meta:
        rule_id = "LAB-002"
        description = "Binary references a shell interpreter path"
        author = "MalvaX project"
        references = "docs/static-analysis.md"
        severity = "low"
    strings:
        $sh = "/bin/sh" ascii
        $bash = "/bin/bash" ascii
    condition:
        any of them
}

rule LAB_File_Activity_Marker
{
    meta:
        rule_id = "LAB-003"
        description = "Binary contains the laboratory temporary-file marker"
        author = "MalvaX project"
        references = "docs/dynamic-analysis.md"
        severity = "info"
    strings:
        $marker = "MALVAX_LAB_TMP" ascii
    condition:
        $marker
}
