// Updated on Wed Oct 28 3:30:50 2020

rule BitcoinTransaction {
    strings:
        $bitcointransaction1 = /[a-fA-F0-9]{64}/ ascii wide
        $bitcointransaction2 = "btc" nocase
        $bitcointransaction3 = "bitcoin" nocase
    condition:
        $bitcointransaction1 and ($bitcointransaction2 or $bitcointransaction3)
}
