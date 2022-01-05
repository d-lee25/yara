rule Ripple {
    strings:
        $cryptocurr = /r[0-9a-zA-Z]{24,34}/ ascii wide
    condition:
        1 of them
}
