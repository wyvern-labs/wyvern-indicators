rule AVrecon_Malware {
    meta:
        name         = "AVrecon SOHO & IoT malware."
        author       = "Wyvern Labs / https://wyvern.ma"
        description  = "Detects AVRecon ELF botnet targeting SOHO ARM routers (maral + mops variants, LE + BE) part of ProxySquid proxy network."
        reference    = "https://blog.wyvern.ma/blog/avrecon-malware-targeting-soho-2026-04/"
        reference    = "https://www.ic3.gov/CSA/2026/260312.pdf"
        reference    = "https://www.ic3.gov/CSA/2026/260312.pdf"
        reference    = "https://www.dgssi.gov.ma/fr/bulletins/avrecon-malware/"
        date         = "2026-03-29"
        tlp          = "WHITE"

    strings:
        $string_one     = "Wazzup, mazafucker" ascii
        $vilka        = "[VILKA]" ascii
        $key          = "vilochka" ascii

        // Campaign (refer tp blog)
        $campaign_maral = "maral" ascii
        $campaign_mops  = "mops"  ascii

        $nvram_memasik = "memasik" ascii
        $nvram_domik   = "domik"   ascii
        $nvram_urlik   = "urlik"   ascii
        $nvram_portik  = "portik"  ascii

     
        $beacon_path  = "/lumi/track.php" ascii
        $fake_pid     = "dnssmasq.pid" ascii
        $hdr1         = "X-Proto-Cookies" ascii
        $hdr2         = "X-Proto-UAgent"  ascii
        $hdr3         = "X-Proto-Version" ascii
        $hdr4         = "X-Proto-System"  ascii
        $hdr5         = "X-Proto-Core"    ascii
        $hdr6         = "X-Proto-Storage" ascii
        $hdr7         = "X-Proto-Jid"     ascii
        $enc_c2_primary  = { 75 7A 6D 7E 33 6D 6D }
        $enc_c2_fallback = { 70 6F 78 7F 72 73 6D 65 33 6D 6D }
        $elf_magic_le = { 7F 45 4C 46 01 01 01 }
        $elf_magic_be = { 7F 45 4C 46 01 02 01 }

    condition:
        any of ($elf_magic_*) at 0
        and filesize < 300KB
        and (
            any of ($string_one, $vilka)
            or
            ($key and 3 of ($nvram_*))
            or
            ($beacon_path and 3 of ($hdr*))
            or
            ($fake_pid and any of ($campaign_maral, $campaign_mops))
            or
            (any of ($enc_c2_*) and any of ($campaign_maral, $campaign_mops))
        )
}