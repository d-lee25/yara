rule Facebook {
    strings: 
        $facebook = /http(s)?:\/\/(www\.)?(m\.)?(facebook|fb)\.com\/[A-z0-9_\-\.]{5,50}\/?/ ascii wide

    condition: 1 of them
}
