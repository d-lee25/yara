//Created on Nov 15 1215 2021

//Create rules for Trezor payment system

rule Trezor{
    strings:
        $string1 = "https://wallet.trezor.io/#/bridge" nocase
        $string2 = "https://suite.trezor.io/web/" nocase
        $string3 = "Trezor-Suite" nocase
	    $string4 = "trezconnect" nocase
	    $string5 = "trezbridge" nocase
	    $string6 = "trezor-bridge" nocase
	    $string7 = "/wallet/trezio.io/" nocase
	    $string8 = /.trezor.io/ nocase
					        
    condition:
        // May add 'Not "third-party"' later if needed here or in PP
        any of ($string*)


}
