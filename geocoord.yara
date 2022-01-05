rule Decimal_NSEW {
    strings: $decimal_nsew = /[-+]?[0-1]?[0-9]{1,2}\.\d{1,8}°?\s*[NSEW][,\s]*[-+]?[0-1]?[0-9]{1,2}\.\d{1,8}°?\s*[NSEW]/ ascii wide
    condition: 1 of them
}

rule Decimal_Degrees {
    strings: $decimal_degrees = /[-+]?[0-1]?[0-9]{1,2}\.\d{1,8}°[,\s]*[-+]?[0-1]?[0-9]{1,2}\.\d{1,8}°/ ascii wide
    condition: 1 of them
}

// This returns too many results right now
/*rule Bare_Decimals {
    strings: 
        $bare_decimals = /[-+]?[0-1]?[0-9]{1,2}\.\d{1,8}[,\t ]+[-+]?[0-1]?[0-9]{1,2}\.\d{1,8}/ ascii wide fullword
    condition: 
        1 of them
}*/

rule Degrees_and_Decimal_Minutes {
    strings: $degrees_and_decimal_minutes = /[-+]?\d{1,3}°\s*\d{1,3}\.\d+['\x92]\s*[NSEW][,\s]*[-+]?\d{1,3}°\s?\d{1,3}\.\d+['\x92]?\s*[NSEW]/ ascii wide
    condition: 1 of them
}

rule Degrees_Minutes_Seconds {
    strings: $degrees_minutes_seconds = /[-+]?\d{1,3}°\s*\d{1,3}['\x92]\s*\d{1,3}(\.\d+)?[\x94"]\s*[NSEW][,\s]*[-+]?\d{1,3}°\s*\d{1,3}['\x92]\s?\d{1,3}(\.\d+)?["\x94]\s*[NSEW]/ ascii wide
    condition: 1 of them
}

rule MGRS {
    strings: $mgrs = /[1-6]?\d[C-X]\s?[A-Z]{2}\s?(\d\s?\d){4,5}/ ascii wide
    condition: 1 of them
}


