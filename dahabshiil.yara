// Updated on Tue Feb 23 11:21:41 2021

rule Dahabshiil {
    strings:
        $remittance1 = /This is to inform you that your remittance to (.{2,15}) has been paid. Thanks and welcome back/ nocase ascii wide
        $remittance2 = /Lacagti aad u dirtay (.{2,25}) wan bixinay. Mahadsanid. Your remittance to (.{2,25}) with reference (.{3,10}) is paid. Thank you/ nocase ascii wide       
        $remittance3 = /ka doono Dahabshiil/ nocase ascii wide       
    condition:
        any of ($remittance*)
}