// Updated on Mon Sept 21 03:21:41 2020

rule EthereumHash {
    strings:
        $cryptocurr = /0x[a-fA-F0-9]{64}/ ascii wide
    condition:
        1 of them
}