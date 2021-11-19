/*
Keywords for airtel 

https://www.airtel.in/bank/addMoney
https://airtel.in/bank/money-transfer-mobile
https://airtel.africa
www.airtelkenya.com
"8800688006" - Note: Airtel payment bank services phone #:
*/

rule Airtel {
    strings:
        $string1 = "https://www.airtel.in/bank/addMoney" nocase
        $string2 = "https://airtel.in/bank/money-transfer-mobile" nocase 
        $string3 = "https://airtel.africa" nocase 
        $string4 = "www.airtelkenya.com" nocase 
   
    condition:
        any of ($string*)
}