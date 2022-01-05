// Updated on Mon Sept 21 03:21:41 2020

rule Monero {
    strings:
        //$cryptocurr1 = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii wide
        $cryptocurr2 = "xmr" nocase
        $cryptocurr3 = "monero" nocase
    condition:
        //$cryptocurr1 and ($cryptocurr2 or $cryptocurr3)
        any of them
}