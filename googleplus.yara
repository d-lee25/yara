rule GooglePlus {
    strings: 
        $google_plus = /https?:\/\/plus\.google\.com\/\d{21}/ ascii wide

    condition: 1 of them
}
