// Updated on Wed Jan 11 03:21:41 2020

rule USDT {
    strings:
        $cryptocurr1 = "usdt" nocase
        $cryptocurr2 = "tether" nocase
        $cryptocurr3 = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/ ascii wide
        $cryptocurr4 = /0x[a-fA-F0-9]{40}/ ascii wide
    condition:
        ($cryptocurr1 or $cryptocurr2) and ($cryptocurr3 or $cryptocurr4)
}