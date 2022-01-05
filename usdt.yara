// Updated on Mon Sept 21 03:21:41 2020

rule USDT {
    strings:
        $usdt1 = "usdt" nocase
        $usdt2 = "tether" nocase
        //$usdt3 = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/ ascii wide
        $usdt4 = /0x[a-fA-F0-9]{40}/ ascii wide
    condition:
        ($usdt1 or $usdt2) and ($usdt3 or $usdt4)
}