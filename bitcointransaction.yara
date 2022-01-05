// Updated on Wed Dec 28 2021

// rule BitcoinTransaction {
//     strings:
//         $cryptocurr1 = /\b[a-fA-F0-9]{64}\b/ ascii wide
//         $cryptocurr2 = "btc" 
//         $cryptocurr3 = "bitcoin" nocase
//         $cryptocurr4 = "BTC"
//     condition:
//         $cryptocurr1 and ($cryptocurr2 or $cryptocurr3 or $cryptocurr4)
// }
