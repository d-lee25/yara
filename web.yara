// rule Email { 
//     strings: $email_address = /([\x80-\xFFa-z0-9!#$%&'*+?^_`{|}~-]+(\.[\x80-\xFFa-z0-9!#$%&'*+?^_`{|}~-]+)*|"([\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\xff]|\\[\x01-\x09\x0b\x0c\x0e-\xff])*")@(([\x80-\xFFa-z0-9]([\x80-\xFFa-z0-9-]*[\x80-\xFFa-z0-9])?\.)+[\x80-\xFFa-z0-9][\x80-\xFFa-z0-9-]*[\x80-\xFFa-z0-9])/ fullword nocase ascii wide
//     condition: 1 of them
// }

rule URL { 
    strings: $url_http = /(ftp|https?):\/\/[-a-z0-9@:%._\+~#=\x80-\xFF]{2,256}\.[a-z0-9\x80-\xFF-]{2,63}([-()a-z0-9@:%_\+.~#?&\/=\x80-\xFF]*)/ ascii wide fullword nocase
    condition: 1 of them
}

// rule IP_Address { 
//     strings: 
//         $ipv4 = /(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])/ ascii wide
//         $ipv6 = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/ ascii wide
//     condition: 1 of them
// }





