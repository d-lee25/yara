// Created on March 3 2020

rule CryptoMiner {
    strings:
        $string1 = /bfgminer/ nocase
        $string2 = /cgminer/ nocase 
        $string3 = /easyminer/ nocase 
     
    condition:
        any of ($string*)
}
