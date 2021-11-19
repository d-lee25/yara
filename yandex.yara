//Created on Sep 23 1315 2021

//Create rules for Yandex payment system

rule Yandex{
    strings:
        $string1 = /yandex dengi/ nocase
        $string2 = "yandex.dengi" nocase
        $string3 = "yoomoney" nocase
        $string4 = "yumoney" nocase
        $string5 = "balance.yandex" nocase

    condition:
        any of them


}