// Updated on Feb 2 12:21:41 2020

rule Alipay {
    strings:
        $string1 = /alipay_withdraw/ nocase
        $string2 = /alipay.iphoneclient/ nocase 
        $string3 = /alipayapp/ nocase 
        $string4 = /Alipay checkout/ nocase 
        $string5 = /HTTP Alipay Password Input/ nocase 
        $string6 = /refund_alipay/ nocase 
        $string7 = /alipaygphone/ nocase 
        $string8 = /alipayobjects/ nocase 
        $string9 = /wallet-android-release-release-alipay/ nocase 
        $string10 = /alipaydeposit/ nocase
	$string11 = /alipay deposit/ nocase
    condition:
        any of ($string*)
}
