// Updated on DEC 28 2021

rule Litecoin {
    strings:
        $cryptocurr1 = /\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b/ ascii wide
        $cryptocurr2 = "ltc" 
        $cryptocurr3 = "litecoin" nocase
        $cryptocurr4 = "LTC"
    condition:
        $cryptocurr1 and ($cryptocurr2 or $cryptocurr3 or $cryptocurr4)
}