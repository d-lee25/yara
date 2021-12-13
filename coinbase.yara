// Updated on Tue May 11 11:21:41 2021

rule Coinbase {
    strings:
        $string1 = /coinbase/ nocase
        $string2 = /coinbase.com/ nocase
        $string3 = /(https?):\/\/coinbase\.com/ nocase
        $string4 = /coinbase wallet/ nocase
    condition:
        any of ($string*)
}