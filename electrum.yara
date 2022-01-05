//Created on Nov 22 0600 2021

//Create rules for Electrum payment system

rule Electrum{
    strings:
        $string1 = "electrum wallet" nocase
        $string2 = "electrum light" nocase
        $string3 = "electrum-pot" nocase
        $string4 = "electrum-seed" nocase
        
    condition:
        any of them


}