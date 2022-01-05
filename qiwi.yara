// Updated on Feb 3 1:21:41 2021

rule Qiwi {
    strings:

        $string1 = /Qiwi wallet/ nocase
        $string2 = /Visa Qiwi wallet/ nocase 


    condition:
        any of ($string*)
}