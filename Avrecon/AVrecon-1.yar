rule AVrecon_Malware_f18ddb10b3f9044fa2f9d1bb5152e388d4f68c2209165b117135fb2490243d2b {
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
       hash1 = "f18ddb10b3f9044fa2f9d1bb5152e388d4f68c2209165b117135fb2490243d2b"
   strings:
      $s1 = "GET /lumi/fmw.php?c=mopsik HTTP/1.0" fullword ascii
      $s2 = "/usr/bin/dnssmasq" fullword ascii
      $s3 = "/var/tmp/dnssmasq" fullword ascii
      $s4 = "/lumi/fmw.php?c=" fullword ascii
      $s5 = "mopsik" fullword ascii
      $s6 = ".mdebug.abi32" fullword ascii
      $s7 = "/etc/init.d/local" fullword ascii
      $s8 = "< 0B4w" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 8KB and
      all of them
}

rule AVrecon_Malware_db3a48697e0dc96054a64e689f45f99a9f21e946c2c5e155b1efd292aecee3e2 {
   meta:
        name         = "AVrecon SOHO & IoT malware."
        author       = "Wyvern Labs / https://wyvern.ma"
        description  = "Detects AVRecon ELF botnet targeting SOHO ARM routers (maral + mops variants, LE + BE) part of ProxySquid proxy network."
        reference    = "https://blog.wyvern.ma"
        reference    = "https://www.ic3.gov/CSA/2026/260312.pdf"
        reference    = "https://www.ic3.gov/CSA/2026/260312.pdf"
        reference    = "https://www.dgssi.gov.ma/fr/bulletins/avrecon-malware/"
        date         = "2026-03-29"
        tlp          = "WHITE"
        hash1        = "db3a48697e0dc96054a64e689f45f99a9f21e946c2c5e155b1efd292aecee3e2"
   strings:
      $s1 = "GET /lumi/fmw.php?c=maral HTTP/1.0" fullword ascii
      $s2 = "/usr/bin/dnssmasq" fullword ascii
      $s3 = "/var/tmp/dnssmasq" fullword ascii
      $s4 = "/lumi/fmw.php?c=" fullword ascii
      $s5 = "/etc/init.d/local" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 5KB and
      all of them
}

rule AVrecon_Malware_sig_48cc6040c15e556bb5827417dcaab74f6059b62ff2ba4800ee2f9c261d2fd993 {
   meta:
       name         = "AVrecon SOHO & IoT malware."
       author       = "Wyvern Labs / https://wyvern.ma"
       description  = "Detects AVRecon ELF botnet targeting SOHO ARM routers (maral + mops variants, LE + BE) part of ProxySquid proxy network."
       reference    = "https://blog.wyvern.ma"
       reference    = "https://www.ic3.gov/CSA/2026/260312.pdf"
       reference    = "https://www.ic3.gov/CSA/2026/260312.pdf"
       reference    = "https://www.dgssi.gov.ma/fr/bulletins/avrecon-malware/"
       date         = "2026-03-29"
       tlp          = "WHITE"
       hash1 = "48cc6040c15e556bb5827417dcaab74f6059b62ff2ba4800ee2f9c261d2fd993"
   strings:
      $s1 = "gear.com" fullword ascii
      $s2 = "326475676B" ascii
      $s3 = "(!PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s4 = "rhrized" fullword ascii
      $s5 = " HTTP/81" fullword ascii
      $s6 = "which  " fullword ascii
      $s7 = "/etc/host;" fullword ascii
      $s8 = "$Id: UPX 3.94 Copyright (C) 1996-2017 the UPX Team. All Rights Reserved. $" fullword ascii
      $s9 = "busybo" fullword ascii
      $s10 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" fullword ascii
      $s11 = "jklm0pqF vw" fullword ascii
      $s12 = ":?icVaddrD" fullword ascii
      $s13 = " ErrO = %d" fullword ascii
      $s14 = "Argum$ liA g" fullword ascii
      $s15 = "MODEL: " fullword ascii
      $s16 = "xSplhd," fullword ascii
      $s17 = "/hlLjztE" fullword ascii
      $s18 = "NSYOWp|k" fullword ascii
      $s19 = "cpuSod' naC" fullword ascii
      $s20 = "ABC8FGHIJKLM" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule AVrecon_Malware_sig_3d43f5b3b2c9142ca0c5cdc4a82f9088e090d077ef61c2297c51b4ccd3085d78 {
   meta:
      name         = "AVrecon SOHO & IoT malware."
      author       = "Wyvern Labs / https://wyvern.ma"
      description  = "Detects AVRecon ELF botnet targeting SOHO ARM routers (maral + mops variants, LE + BE) part of ProxySquid proxy network."
      reference    = "https://blog.wyvern.ma"
      reference    = "https://www.ic3.gov/CSA/2026/260312.pdf"
      reference    = "https://www.dgssi.gov.ma/fr/bulletins/avrecon-malware/"
      date         = "2026-03-29"
      tlp          = "WHITE"
      hash1 = "3d43f5b3b2c9142ca0c5cdc4a82f9088e090d077ef61c2297c51b4ccd3085d78"
   strings:
      $s1 = "/usr/sbin/xmldbc -g /runtime/device/modelname" fullword ascii
      $s2 = "326475676B327A78736D65337E687E" ascii
      $s3 = "757A6D7E336D6D" ascii
      $s4 = "2A2D2B4E2A252A4E2A2F2A2E2B4C2B282F242E2E2B4C2B4C" ascii
      $s5 = "nvram_set Password `cat /tmp/p`" fullword ascii
      $s6 = " -g /device/" fullword ascii
      $s7 = "'| grep -v 'grep' | awk '{print $1}' | grep -v " fullword ascii
      $s8 = "[-][util_tcp_connection] Connect call failed! Errno = %d" fullword ascii
      $s9 = " -s /device/" fullword ascii
      $s10 = "/model.txt" fullword ascii
      $s11 = " hostname" fullword ascii
      $s12 = "/sbin/version" fullword ascii
      $s13 = "dnssmasq.pid" fullword ascii
      $s14 = "Remote I/O error" fullword ascii
      $s15 = "[~] Access granted!" fullword ascii
      $s16 = "X-Proto-UAgent: " fullword ascii
      $s17 = "cat /etc/hostname" fullword ascii
      $s18 = " -ltnp | grep :" fullword ascii
      $s19 = "vilochka" fullword ascii
      $s20 = "busybox" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}