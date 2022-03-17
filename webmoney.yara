// Updated on Tue Dec 16 10:31:41 2020

rule Webmoney {
    strings:
        $string1 = /Webmoney Notification/ nocase
        $string2 = /wmtransfer.com/ nocase 
        $string3 = /WEBMONEY_ID/ nocase
        $string4 = /WMID/ nocase
        $string5 = /WM-purse/ nocase
        $string6 = /webmoney transfer/ nocase
        $string7 = /balanceWebMoney/ nocase 
       	$string8 = /webmoney keeper/ nocase
	    $string9 = /webmoney activate notification/ nocase
	    $string10 = /webmoney keep/ nocase
    condition:
        any of ($string*)
}
