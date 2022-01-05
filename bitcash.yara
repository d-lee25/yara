// rule Bitcash {
//     strings:
//         $cryptocurr1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii wide
//         $cryptocurr2 = /(bitcoincash:)?(q|p)[a-z0-9]{41}/ ascii wide
//         $cryptocurr3 = /(BITCOINCASH:)?(Q|P)[A-Z0-9]{41}/ ascii wide
//     condition:
//         1 of them
// }