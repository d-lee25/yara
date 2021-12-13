rule Bitcoin {
    strings:
        $bitcoin1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii wide
        $bitcoin2 = /(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}/ ascii wide
    condition:
        1 of them
}

rule Bitcash {
    strings:
        $bitcash1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii wide
        $bitcash2 = /(bitcoincash:)?(q|p)[a-z0-9]{41}/ ascii wide
        $bitcash3 = /(BITCOINCASH:)?(Q|P)[A-Z0-9]{41}/ ascii wide
    condition:
        1 of them
}

rule Ethereum {
    strings:
        $ethereum1 = /0x[a-fA-F0-9]{40}/ ascii wide
    condition:
        1 of them
}

rule Ripple {
    strings:
        $ripple1 = /r[0-9a-zA-Z]{24,34}/ ascii wide
    condition:
        1 of them
}



