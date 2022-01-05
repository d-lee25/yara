rule Twitter {
 strings: 
        $twitter = /http(s)?:\/\/(\w*\.)?twitter\.com\/[A-z0-9_]{8,}\/?/ ascii wide

 condition: 1 of them
}
