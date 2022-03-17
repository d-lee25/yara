// Created on March 7 2022

rule IndexWallet {
    strings:
        $cryptocurr1 = /index wallet/ nocase
        $cryptocurr2 = /coin/ nocase
        $cryptocurr3 = /crypto/ nocase
    condition:
        all of them
}