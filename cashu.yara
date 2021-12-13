// Updated on Feb 3 1:21:41 2021

rule CashU {
    strings:
  
        $main = "cashu" nocase

        $string1 = /dailylimiterror/ nocase
        $string2 = /transaction date/ nocase 
        $string3 = /under the transaction number/ nocase 
        $string4 = /support team/ nocase 
        $string5 = /please note that your account is active/ nocase    
        $string6 = /cash vouchers/ nocase 
        $string7 = /Merchant KYC Form/ nocase 
        $string8 = /confirmation of your purchase via cashu/ nocase 
        $string9 = /kindly log into your merchant account on cashu/ nocase   
        $string10 = /www.cashu.com-login-site/ nocase
        $string11 = "bit.ly/cashu-ecards" nocase

    condition:
        any of ($string*) and $main
}