// Updated on Thu Nov 5 11:21:41 2020

rule Poloniex {
    strings:
        $string1 = /poloniex/ nocase
        $string2 = /poloniex.com/ nocase
        $string3 = /(https?):\/\/poloniex\.com/ nocase
    condition:
        any of ($string*)
}