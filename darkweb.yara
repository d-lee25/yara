// Updated on Wed Feb 10 03:21:41 2021

rule Tor  {
    strings:
        $string1 = ".onion" nocase
        $string2 = "hidden-services-" nocase 
        $string3 = "ntor-onion-key" nocase 
        $string4 = "onionland" nocase 
        $string5 = "url onion_link" nocase 
        $string6 = "configured on or more hidden services" nocase 
        $string7 = "to/from Tor Hidden Services" nocase 
        $string8 = "tor-browser" nocase 
        $string9 = "onionshare" nocase 
        $string10 = "Description-md5" nocase 
        $string11 = "torRefSpoofer.js" nocase 
        $string12 = "torrc." nocase 
       
        $basic1 = "anonymity network" nocase 
        $basic2 = "tor" nocase 


    condition:
        any of ($string*) or ($basic1 and $basic2) 
}