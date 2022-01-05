rule Ethereum {
    strings:
        $cryptocurr = /0x[a-fA-F0-9]{40}/ ascii wide
    condition:
        1 of them
}