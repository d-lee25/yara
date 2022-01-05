// Updated on Mon Sept 21 03:21:41 2020

rule DAI {
    strings:
        $cryptocurr1 = /0x[a-fA-F0-9]{40}/ ascii wide
        $cryptocurr2 = /dai/ nocase ascii wide
    condition:
        $cryptocurr1 and $cryptocurr2
}
