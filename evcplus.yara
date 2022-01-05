// Updated on May 5 1:21:41 2021

rule EVCPlus {
    strings:
        $string1 = "EVC Plus"
        $string2 = "Golis EVC" 
    condition:
        any of ($string*)
}