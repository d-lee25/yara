// Updated on May 5 1:21:41 2021

rule EVC_Plus {
    strings:
        $string1 = "EVC Plus"
        $string2 = "Golis EVC" 
    condition:
        any of ($string*)
}