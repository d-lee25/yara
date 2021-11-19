//Created on Nov 15 1200 2021

//Create rules for Paypal payment system

rule Paypal{
    strings:
        $string1 = "PayPal Balance" nocase
        $string2 = "Paypal Cash" nocase
        $string3 = "https://www.paypal.com/signin" nocase
        
    condition:
        any of them


}