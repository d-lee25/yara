rule American_Express {
    // AMEX expected length is 15
    strings: $card_number = /\b3[47][0-9]{13}\b/ ascii wide
    condition: 1 of them
}

rule Diners_Club {
    // Diners club Blanche: 14 char, International: 14 char, US/CD: 16 char
    strings: $card_number = /\b3(0[0-5]|[68][0-9])[0-9]{11}\b/ ascii wide
    condition: 1 of them
}


rule Discover {
    // Discover expcted 16 char
    strings: $card_number = /\b6(011|5[0-9]{2})[0-9]{12}\b/ ascii wide
    condition: 1 of them
}


rule JCB {
    // JCB expected 16 char
    strings: $card_number = /\b(2131|1800|35\d{3})\d{11}\b/ ascii wide
    condition: 1 of them
}

rule Maestro {
    // Maestro exptect 12-19 char
    strings: $card_number = /\b(5[0678]\d\d|6304|6390|67\d\d)\d{8,15}\b/ ascii wide
    condition: 1 of them
}

rule Mastercard {
    // Mastercard expected 16 char
    strings: $card_number = /\b(5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b/ ascii wide
    condition: 1 of them
}

rule Visa {
    // Visa expected 16 char
    strings: $card_number = /\b4[0-9]{12}([0-9]{3})?\b/ ascii wide
    condition: 1 of them
}