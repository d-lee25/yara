// Created on March 2, 2022

rule WeChat {
    strings:
        $string1 = "WeChat Deposit" nocase
      
    condition:
        any of ($string*)
}
