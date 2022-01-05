// Updated on Tue Feb 23 11:21:41 2021

rule Mpesa {
    strings:
        $balance1 = /New M-pesa balance is \d+/ nocase ascii wide
        $balance2 = /\w{11} Confirmed.You have received (.{4,35})from (.{10,15}) - (.{4,40}) on (.{6,10}) at (.{8}) New M-Pesa balance is (.{4,35})[.]/ nocase ascii wide
    condition:
        any of ($balance*)
}