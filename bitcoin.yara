rule Bitcoin {
    strings:
        $cryptocurr1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii wide
        $cryptocurr2 = /(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}/ ascii wide
    condition:
        1 of them
}