rule Instagram {
    strings: 
        $instagram = /https?:\/\/(www\.)?instagram\.com\/[A-Za-z0-9_]{8,30}/ ascii wide

    condition: 1 of them
}
