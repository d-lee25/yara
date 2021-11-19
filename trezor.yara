//Created on Nov 15 1215 2021

//Create rules for Trezor payment system

rule Trezor{
    strings:
        $string1 = "https://wallet.trezor.io/#/bridge" nocase
        $string2 = "https://suite.trezor.io/web/" nocase
        $string3 = "Trezor-Suite" nocase
        
    condition:
        any of them


}