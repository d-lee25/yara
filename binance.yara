// Updated on Thu May 6 11:21:41 2020

rule Binance {
    strings:
        $string1 = /binance/ nocase
        $string2 = /binance.com/ nocase
        $string3 = /(https?):\/\/binance\.com/ nocase
        $string4 = /(https?):\/\/binance\.us/ nocase
    condition:
        any of ($string*)
}